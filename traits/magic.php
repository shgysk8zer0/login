<?php
namespace shgysk8zer0\Login\Traits;
use \shgysk8zer0\Core\{PDO};
trait Magic
{
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
}
