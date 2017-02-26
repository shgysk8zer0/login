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
	use Traits\Cookie;
	use Traits\Serialize;
	use Traits\Magic;
	use Traits\Permissions;
	use Traits\Tables;
	use Traits\Data;

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

	public static $check_wp_pass = false;

	private static $_instances = array();

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
	 * Update password for user
	 * @param  String $password The new password
	 * @return Bool             Whether or not the transaction was successful
	 */
	public function updatePassword(String $password): Bool
	{
		$this->_pdo->beginTransaction();
		try {
			$stm = $this->_pdo->prepare(
				'UPDATE `users`
				SET `password`   = :pass
				WHERE `username` = :user
				LIMIT 1;'
			);
			$stm->bindParam(':user', $this->username);
			$hash = static::passwordHash($password);
			$stm->bindParam(':pass', $hash);
			if ($stm->execute() and $this($this->username, $password)) {
				return $this->_pdo->commit();
			} else {
				throw new \RuntimeException('Error updating password');
			}
		} catch (\Throwable $e) {
			$this->_pdo->rollBack();
			trigger_error($e->getMessage());
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
