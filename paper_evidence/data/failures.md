# B18 — Failure cases

Real corpus lines where the screening classifier disagrees with the hand label. Not selected for effect: these are every disagreement class that occurs, with the first example of each.

## hand label `USE`, classifier said `MENTION`

* **repository** openwrt/openwrt
* **location** `package/kernel/lantiq/ltq-deu/src/ifxmips_aes.c:1922`
* **family** AES
* **source** `printk (KERN_ERR "IFX gcm_aes initialization failed!\n");`
* **why the label** registers a real AES-GCM driver in the DEU crypto module

## hand label `MENTION`, classifier said `USE`

* **repository** TheAlgorithms/Python
* **location** `ciphers/rsa_factorization.py:4`
* **family** RSA
* **source** `The program can efficiently factor RSA prime number given the private key d and`
* **why the label** module docstring describing an RSA factorisation exercise

## hand label `USE`, classifier said `ABSENT`

* **repository** fruitcake/laravel-debugbar
* **location** `src/Support/Explain.php:67`
* **family** HS256
* **source** `return hash_hmac('sha256', "{$connection}::{$sql}::{$bindings}", config('app.key'));`
* **why the label** hash_hmac('sha256', ...) computes a real HMAC-SHA256, though not a JOSE header

## hand label `MENTION`, classifier said `ABSENT`

* **repository** openwrt/openwrt
* **location** `package/kernel/lantiq/ltq-deu/src/ifxmips_deu.c:98`
* **family** 3DES
* **source** `printk (KERN_ERR "IFX DES initialization failed!\n");`
* **why the label** an error message string; the surrounding driver is single DES, not 3DES

## hand label `ABSENT`, classifier said `MENTION`

* **repository** allinurl/goaccess
* **location** `src/settings.c:90`
* **family** LMS
* **source** `"%h - %e [%d:%t %^] \"%r\" %s %b \"%R\" \"%u\" %^ \"%v\" \"%U\" %Lms" /* Traefik's CLF flavor with header */`
* **why the label** %Lms is a Traefik log-format specifier, not the LMS signature scheme

