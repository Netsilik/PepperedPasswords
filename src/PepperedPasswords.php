<?php
namespace Netsilik\Lib;

/**
 * @package Scepino\Lib
 * @copyright (c) 2010-2016 Scepino (http://scepino.com)
 * @license EUPL-1.1 (European Union Public Licence, v1.1)
 */

/**
 * Handle peppered password hashes
 */
final class PepperedPasswords
{
	
	/**
	 * The algorithm to use for calculating the HMac of the password
	 */
	const HMAC_ALGORITHM = 'sha256';
	
	/**
	 * @var string $_pepper The pepper value
	 */
	private $_pepper;
	
	/**
	 * Constructor
	 *
	 * @param string $pepper  The pepper to use as the HMac key
	 */
	public function __construct(string $pepper)
	{
		$this->_pepper = $pepper;
	}
	
	/**
	 * Calculate the peppered hash of a password
	 *
	 * @param string $password The password to calculate the hash for
	 *
	 * @return string The peppered hash of the password supplied
	 */
	public function hash($password)
	{
		return password_hash($this->_hmac($password), PASSWORD_DEFAULT);
	}
	
	/**
	 * Verify a password against its peppered hash
	 *
	 * @param string $password     The password to verify
	 * @param string $passwordHash The password hash to verify the password against
	 *
	 * @return bool True if the password is correct, false otherwise
	 */
	public function verify($password, $passwordHash)
	{
		return password_verify($this->_hmac($password), $passwordHash);
	}
	
	/**
	 * Compute the HMac for the password
	 *
	 * @return string the HMac for the supplied password
	 */
	private function _hmac($password)
	{
		return hash_hmac(self::HMAC_ALGORITHM, $password, $this->_pepper, true);
	}
}
