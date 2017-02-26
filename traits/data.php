<?php
namespace shgysk8zer0\Login\Traits;

trait Data
{

	protected $_user_data  = array();
	/**
	 * Private method for retrieving data
	 * @return Array Data to be shared, such as for `jsonSerialize`
	 */
	protected function _getData(): Array
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
	protected function _setData(\stdClass $data)
	{
		$this->id       = $data->id;
		$this->username = $data->username;
		$this->email    = $data->email;
		$this->password = $data->password;
		unset($data->id ,$data->username, $data->email, $data->password);
		$this->_getPermsissions($data->status);
		$this->{self::MAGIC_PROPERTY} = get_object_vars($data);
	}

	abstract function _getPermsissions(Int $role_id): \stdClass;
}
