<?php
/**
 * @author Chris Zuber <shgysk8zer0@gmail.com>
 * @package shgysk8zer0\Login
 * @version 1.0.0
 * @copyright 2017, Chris Zuber
 * @license http://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
namespace shgysk8zer0\Login;

use \shgysk8zer0\Core\{PDO};
use \shgysk8zer0\PHPCrypt\{Traits\AES, Traits\Password};
use \stdClass;
use \ArrayObject;

class User implements \jsonSerializable, \Serializable
{
	use WP_Pass;
	use Password;
	use AES;

	const MAGIC_PROPERTY = '_user_data';

	const USER_TABLE     = 'users';

	const DATA_TABLE     = 'user_data';

	const KEY            = 'user';

	public $id           = null;

	public $username     = null;

	public $email        = null;

	private $password    = null;

	private $_pdo        = null;

	private $_db_creds   = null;

	private $_user_data  = array();

	private $_tables     = array();

	public static $check_wp_pass = false;

	private static $_instances = array();

	public static  $expires = '+1 month';

	private $_permissions;

	/**
	 * Restore instance. Creates if instances doesn't exist
	 * @param  String $config DB credentials file
	 * @return self           New or existing instance of self
	 */
	final static public function load(String $config): self
	{
		if (! array_key_exists($config, static::$_instances)) {
			static::$_instances[$config] = new self($config);
		}
		return static::$_instances[$config];
	}

	/**
	 * Create a new instance from database credentials file
	 * @param string $creds path/to/creds.json
	 */
	public function __construct(String $creds = PDO::DEFAULT_CON)
	{
		$this->_db_creds = $creds;
		$this->_pdo = PDO::load($creds);
		if (
			array_key_exists('PHP_AUTH_USER', $_SERVER)
			and array_key_exists('PHP_AUTH_PW', $_SERVER)
		) {
			$this($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
		}
	}

	/**
	 * Login using usrename/email and passowrd
	 * @param  String $user     user@example.com or username
	 * @param  String $password Password
	 * @return Bool             Whether or not login was successful
	 */
	public function __invoke(String $user, String $password): Bool
	{
		$stm = $this->_pdo->prepare($this->_getQuery());
		$stm->bindParam(':user', $user, PDO::PARAM_STR);
		if ($stm->execute() and $data = $stm->fetchObject()) {
			if (
				isset($data->password)
				and ($this->passwordVerify($password, $data->password))
			) {
				$this->_setData($data);
				return true;
			} elseif (
				static::$check_wp_pass === true and isset($data->password)
				and ($this->CheckPassword($password, $data->password))
			) {
				$hash = $this->passwordHash($password);
				$update = $pdo->prepare(
					'UPDATE `users`
					SET `password` = :hash
					WHERE `username` = :user
					LIMIT 1;'
				);
				$update->bindParam(':hash', $hash);
				$update->bindParam(':user', $data->username);
				if ($update->execute()) {
					$data->password = $hash;
					$this->_setData($data);
					return true;
				} else {
					trigger_error('Error updating password');
					return false;
				}
			} else {
				return false;
			}
		}
		return false;
	}

	/**
	 * Magic getter
	 * @param  String $prop Name of property
	 * @return Mixed        Its value
	 */
	public function __get(String $prop)
	{
		return $this->{self::MAGIC_PROPERTY}[$prop] ?? null;
	}

	/**
	 * Magic isset method
	 * @param  String  $prop Name of property
	 * @return boolean       Whether or not it is set
	 */
	public function __isset(String $prop): Bool
	{
		return array_key_exists($prop, $this->{self::MAGIC_PROPERTY});
	}

	/**
	 * Method used to convert class object to string
	 * @return string Username
	 */
	public function __toString(): String
	{
		return $this->username;
	}

	/**
	 * Method used when calling debugging functions, such as `var_dump`
	 * @return Array Data array
	 */
	public function __debugInfo(): Array
	{
		return $this->_getData();
	}

	/**
	 * Method used when converting class object to JSON using `json_encode`
	 * @return Array Data array
	 */
	public function jsonSerialize(): Array
	{
		return $this->_getData();
	}

	/**
	 * Class `serialize` method
	 * @return String Serialized class data
	 */
	public function serialize(): String
	{
		$expires = is_string(static::$expires)
			? strtotime(static::$expires)
			: static::$expires;

		$data = [
			'username' => $this->username,
			'tables'   => $this->_tables,
			'db_creds' => $this->_db_creds,
			'expires'  => $expires,
		];
		return serialize($data);
	}

	/**
	 * Method used to `unserialize`
	 * @param  String $data Serialized data
	 * @return void
	 */
	public function unserialize($data)
	{
		$data = @unserialize($data);
		$data = new ArrayObject($data, ArrayObject::ARRAY_AS_PROPS);
		if (isset($data, $data->username, $data->expires, $data->db_creds, $data->tables)) {
			static::$expires = $data->expires;
			unset($data->expires);
			$this->_db_creds = $data->db_creds;
			$this->_pdo      = PDO::load($this->_db_creds);
			$this->_tables   = $data->tables;
			$stm = $this->_pdo->prepare($this->_getQuery());
			$stm->bindParam(':user', $data->username, PDO::PARAM_STR);

			if ($stm->execute() and $data = $stm->fetchObject()) {
				$this->_setData($data);
			} else {
				$this->logout();
			}
			static::$_instances[$this->_db_creds] = $this;
		}
	}

	/**
	 * Create a user by searching for username or email
	 * @param  String $db_creds Datbase credentials file
	 * @param  String $query    Username or email
	 * @return self
	 */
	public static function search(String $db_creds, String $query): self
	{
		$user = new self($db_creds);
		$stm = $user->_pdo->prepare($user->_getQuery());
		$stm->bindParam(':user', $query);
		$stm->execute();

		if ($data = $stm->fetchObject()) {
			$user->_setData($data);
			unset($user->password, $user->status);
		}
		return $user;
	}

	/**
	 * Check if a user has permission for a given action
	 * @param  String $permission Permission being checked
	 * @return Bool               Whether or not user has permission
	 */
	public function hasPermission(String $permission): Bool
	{
		return @isset($this->_permissions->{$permission})
			and $this->_permissions->{$permission} === '1';
	}

	/**
	 * Sets login cookie, optionally using encryption
	 * @param  String $key        Sets `$_COOKIE[$key]`
	 * @param  String $crypto_pwd Optional password to encrypt with
	 * @return self               Return self to make chainable
	 */
	public function setCookie(String $key = self::KEY, String $crypto_pwd = null): self
	{
		if (is_string($crypto_pwd)) {
			$cookie = static::encrypt(@serialize($this), $crypto_pwd);
		} else {
			$cookie = base64_encode(@serialize($this));
		}
		static::_cookie($key, $cookie, static::$expires);
		return $this;
	}

	/**
	 * Save to session
	 * @param  String $key Sets `$_SESSION[$key]`
	 * @return self        Return self to make chainable
	 */
	public function setSession(String $key = self::KEY): self
	{
		$_SESSION[$key] = @serialize($this);
		return $this;
	}

	/**
	 * Logs a user out, clearing data
	 * @param  String $key `$_COOKIE[$key]` and `$_SESSION[$key]`
	 * @return self        Return self to make chainable
	 */
	public function logout(String $key = self::KEY): self
	{
		if (array_key_exists($key, $_COOKIE)) {
			static::_cookie($key, null, 1);
		}
		if (session_status() === PHP_SESSION_ACTIVE) {
			unset($_SESSION[$key]);
		}
		$this->id = null;
		$this->username = null;
		$this->password = null;
		$this->{self::MAGIC_PROPERTY} = array();
		return $this;
	}

	/**
	 * Checks if a MySQL table is set to be used for setting user data
	 * @param  String $table Name of table
	 * @return Bool          Whether or not is has already been added
	 */
	public function hasTable(String $table): Bool
	{
		return in_array($table, $this->_tables);
	}

	/**
	 * Retrieves a list of all extra MySQL tables used for user data
	 * @return Array [table1, ...]
	 */
	public function getTables(): Array
	{
		return array_map(function($table)
		{
			return sprintf('`%s`', preg_replace('/[^\w\- ]/', null, $table));
		}, $this->_tables);
	}

	/**
	 * Adds a MySQL table to the list of tables used for user data
	 * @param  String $table Name of table
	 * @return Bool          Whether or not it was appended to the list
	 */
	public function addTable(String $table): Bool
	{
		if (! $this->hasTable($table)) {
			array_push($this->_tables, $table);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Restore login from `$_COOKIE` or `$_SESSION`
	 * @param  String $key        Name of key in `$_COOKIE` or `$_SESSION`
	 * @param  String $db_creds   path/to/db_creds.json
	 * @param  String $crypto_pwd Optional password to use to decrypt login cookie
	 * @return self               The restored and possibly logged in user
	 */
	public static function restore(
		String $key        = self::KEY,
		String $db_creds   = PDO::DEFAULT_CON,
		String $crypto_pwd = null
	): self
	{
		try {
			if (! is_string($db_creds)) {
				throw new \InvalidArgumentException('Trying to restore without database credentials.');
			} elseif (array_key_exists($db_creds, static::$_instances)) {
				$user = static::$_instances[$db_creds];
			} elseif (session_status() === PHP_SESSION_ACTIVE and array_key_exists($key, $_SESSION)) {
				$user = @unserialize($_SESSION[$key]);
				if (!$user) {
					unset($_SESSION[$key]);
					throw new \RuntimeException('Unable to restore from session.');
				}
			} elseif (array_key_exists($key, $_COOKIE)) {
				if (is_string($crypto_pwd)) {
					$user = @unserialize(@static::decrypt($_COOKIE[$key], $crypto_pwd));
				} else {
					$user = @unserialize(@base64_decode($_COOKIE[$key]));
				}
				if (!$user) {
					static::_cookie($key, null, 1);
					unset($_COOKIE[$key]);
					throw new \RuntimeException('Unable to restore from cookie.');
				} elseif (session_status() === PHP_SESSION_ACTIVE) {
					$_SESSION[$key] = @serialize($user);
				}
			} else {
				$user = new self($db_creds);
			}
		} catch (\Throwable $e) {
			trigger_error($e->getMessage());
		} finally {
			if (isset($user) and is_object($user) and $user instanceof self) {
				static::$_instances[$db_creds] = $user;
				if (static::_isExpired($user::$expires)) {
					$user->logout();
				}
			} else {
				$user = static::$_instances[$db_creds] = new self($db_creds);
				if (session_status() === PHP_SESSION_ACTIVE) {
					$_SESSION[$key] = @serialize($user);
				}
			}
			return $user;
		}
	}

	/**
	 * Private method for setting cookies more easily
	 * @param  String  $key     Cookie name
	 * @param  String  $value   Value to set it to
	 * @param  Mixed   $expires Expiration timestamp
	 * @return Bool             Whether or not the cookie was set
	 */
	private static function _cookie(String $key, String $value = null, $expires = 1): Bool
	{
		if (isset($value)) {
			$_COOKIE[$key] = $value;
		} else {
			unset($_COOKIE[$key]);
		}

		return setcookie(
			$key,
			$value,
			is_string($expires) ? strtotime($expires) : $expires,
			'/',
			$_SERVER['HTTP_HOST'],
			array_key_exists('HTTPS', $_SERVER),
			true
		);
	}

	/**
	 * Does timestamp comparision
	 * @param  Mixed   $expires Expiration timestamp or date string
	 * @return Bool             Whether or not it is less than current time
	 */
	private static function _isExpired($expires): Bool
	{
		if (is_int($expires)) {
			return $expires < time();
		} elseif (is_string($expires)) {
			return strtotime($expires) < time();
		} else {
			return true;
		}
	}

	/**
	 * Private method for retrieving data
	 * @return Array Data to be shared, such as for `jsonSerialize`
	 */
	private function _getData(): Array
	{
		return array_merge([
			'id'       => $this->id,
			'username' => $this->username,
			'email'    => $this->email,
		], $this->{self::MAGIC_PROPERTY});
	}

	/**
	 * Private method for setting data
	 * @param Array $data Data, such as from a SQL query
	 */
	private function _setData(stdClass $data)
	{
		$this->id       = $data->id;
		$this->username = $data->username;
		$this->email    = $data->email;
		$this->password = $data->password;
		unset($data->id ,$data->username, $data->email, $data->password);
		$this->_permissions = $this->_getPermsissions($data->status);
		$this->{self::MAGIC_PROPERTY} = get_object_vars($data);
	}

	/**
	 * Retrieves permissions from `permissions` table and returns as object
	 * @param  Int       $role_id `subscribers`.`status`
	 * @return stdClass           {"$permissionName": "1" || "0", ...}
	 */
	private function _getPermsissions(Int $role_id): stdClass
	{
		$stm = $this->_pdo->prepare(
			'SELECT *
			FROM `permissions`
			WHERE `id` = :role
			LIMIT 1;'
		);
		$stm->bindParam(':role', $role_id);
		if ($stm->execute() and $permissions = $stm->fetchObject()) {
			unset($permissions->id, $permissions->roleName);
		} else {
			$permissions = new stdClass();
		}
		return $permissions;
	}

	/**
	 * Returns SQL for use in perpared statement for logging in
	 * @return String SELECT statement
	 */
	private function _getQuery(): String
	{
		return 'SELECT * FROM `users`
		JOIN (
			`user_data`,
			`subscribers`
		) ON (
			`user_data`.`id` = `users`.`id`
			AND `subscribers`.`id` = `users`.`id`
		)
		WHERE `users`.`email` = :user
		OR `users`.`username` = :user
		LIMIT 1;';
	}
}
