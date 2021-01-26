<?php
namespace Netsilik\Lib;

/**
 * @package       Scepino\Lib
 * @copyright (c) 2010-2021 Netsilik (http://netsilik.nl)
 * @license       MIT
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
	 * @var array The options for the PASSWORD_DEFAULT hashing algorithm
	 *            See {@link https://www.php.net/password_hash} for more details
	 */
	private $_options;
	
	/**
	 * Constructor
	 *
	 * @param string $pepper  The pepper to use as the HMac key
	 * @param array  $options The options for the PASSWORD_DEFAULT hashing algorithm
	 */
	public function __construct(string $pepper, array $options = [])
	{
		$this->_pepper = $pepper;
		
		$this->_options = $options;
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
		return password_hash($this->_hmac($password), PASSWORD_DEFAULT, $this->_options);
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
