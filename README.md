# laravel-wordpress-auth
Laravel WordPress 8.6 Password Bridge
/**
 * Check if the provided password matches the stored hash.
 *
 * This function handles both the current password hashing strategy (with a `$wp` prefix) 
 * and a fallback to a legacy password hashing method using the `PasswordHash` class.
 *
 * Current Strategy:
 * - Detects the `$wp` prefix in the stored password.
 * - Hashes the input password using HMAC-SHA384 with a static key (`wp-sha384`).
 * - Encodes the result in base64.
 * - Uses `password_verify()` to compare the encoded hash with the stored value (after removing the `$wp` prefix).
 *
 * Legacy Strategy:
 * - Falls back to the older `PasswordHash` class method.
 * - This typically uses a portable PHPass implementation with base-64 encoded hashes.
 *
 * @param string $inputPassword   The plain text password input by the user.
 * @param string $storedPassword  The hashed password retrieved from storage (database).
 *
 * @return bool  Returns true if the password is correct, false otherwise.
 */

protected function checkPassword(string $inputPassword, string $storedPassword): bool {

   $check = false;
    
    if (str_starts_with($storedPassword, '$wp')) {
        // Check the password using the current prefixed hash.
        $password_to_verify = base64_encode(hash_hmac('sha384', $inputPassword, 'wp-sha384', true));
        $check = password_verify($password_to_verify, substr($storedPassword, 3));
    } else {
        // Fall back to the legacy password checking method
        $passwordHasher = new PasswordHash(8, true);
        $check = $passwordHasher->checkPassword($inputPassword, $storedPassword);
    }
    
    return $check;
}
