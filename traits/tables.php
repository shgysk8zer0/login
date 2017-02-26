<?php
namespace shgysk8zer0\Login\Traits;

trait Tables
{
	protected $_tables = array();
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
}
