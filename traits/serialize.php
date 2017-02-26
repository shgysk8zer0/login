<?php
namespace shgysk8zer0\Login\Traits;
use \shgysk8zer0\Core\{PDO};
use \ArrayObject;
use \stdClass;
trait Serialize
{
	/**
	 * Class `serialize` method
	 * @return String Serialized class data
	 */
	final public function serialize(): String
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
	final public function unserialize($data)
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

	abstract function _getQuery(): String;
	abstract function _setData(stdClass $data);
	abstract function logout();
}
