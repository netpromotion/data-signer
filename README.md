# Data Signer for PHP

## Examples

### Password reset

```php
/** @var int $userId
/** @var Netpromotion\DataSigner\DataSignerInterface $signer */
$token = (string) $signer->withDomain('user.reset_password')->signData($userId, 12 * 3600);
send_reset_password_email($userId, $token);
```

```php
/** @var Netpromotion\DataSigner\DataSignerInterface $signer */
$userId = $signer->withDomain('user.reset_password')->getData($_GET['token']);
set_password($userId, $_POST['new_password']);
```
