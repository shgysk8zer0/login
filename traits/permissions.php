<?php
namespace shgysk8zer0\Login\Traits;
use \stdClass;
trait Permissions
{
	protected $_permissions;
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
	 * Retrieves permissions from `permissions` table and returns as object
	 * @param  Int       $role_id `subscribers`.`status`
	 * @return stdClass           {"$permissionName": "1" || "0", ...}
	 */
	protected function _getPermsissions(Int $role_id): stdClass
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
		return $this->_permissions = $permissions;
	}
}
