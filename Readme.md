Peppered Password Hashing
=========================

Secure password hashing using HMAC before (BCrypt) Hash.

---

MIT Licence

Unless required by applicable law or agreed to in writing, software
distributed under the Licence is distributed on an "AS IS" basis,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

Contact: info@netsilik.nl  
Latest version available at: https://gitlab.com/Netsilik/PepperedPasswords


Installation
------------

```
composer require netsilik/peppered-passwords
```

Usage
-----

**Hashing new passwords**

```
namespace My\Name\Space;

use Netsilik\Lib\PepperedPasswords;

$pepper = hex2bin(env('PEPPER')); // The binary pepper value, stored as a hexadecimal string

$hasher = new PepperedPasswords($pepper);
$hash = $hasher->hash($new_plaintext_password); // Story $hash in the user's record
```

**Verifying passwords**

```
namespace My\Name\Space;

use Netsilik\Lib\PepperedPasswords;

$pepper = hex2bin(env('PEPPER')); // The binary pepper value, stored as a hexadecimal string

$hasher = new PepperedPasswords($pepper);
if ($hasher->verify($new_plaintext_password, $hash)) { // $hash retrieved from the user's record
    echo 'Password ok.';
} else {
    echo 'Wrong credentials.'; 
}
```
