# Data Signer for PHP

Package for exchange of trusted read-only data over the Internet.
The data itself are **not encrypted**, only signed - it can be leaked, but not changed.

## How to use it

### Password reset over token

```php
/** @var Netpromotion\DataSigner\DataSignerInterface $signer */
$tokenForPasswordReset = json_encode($signer->withDomain('accounts.reset_password')->signData([
  'user_id' => $user->getId(),
  'valid_until' => time() + 3600,
]));
send_reset_password_message($user, $tokenForPasswordReset);
```
```php
/** @var Netpromotion\DataSigner\DataSignerInterface $signer */
$dataForPasswordReset = $signer->withDomain('accounts.reset_password')->getData($_GET['tokenForPasswordReset']);
if (time() <= $dataForPasswordReset['valid_until']) {
  reset_password($dataForPasswordReset['user_id'])
} else {
  throw new Exception('Expired token');
}
```
