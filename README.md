----TR-----
Kullanıcıdan bir girdi alan, bu girdiyi hashleyen ve daha sonrasında hashi de md5 ile şifrleeyen bir algortimadır.
 Bu md5 şifrelemeye özgü bir adet key üretir. Şifrelenmiş metini çözmek içinse verilen anahtar ile ilk önce md5 şifrelemeyi tersine çevirilmesi gerekmektedir.
 Daha sonrasında kullanıcının verdiği wordlist ile hashleme yaparka eşleşme yakalamaya çalışır.
 Eşleşme sağlanırsa açık metni ekrana basar.

 ----EN----
 The algorithm that takes user input, hashes it, and then encrypts the hash with MD5 is a specific type of encryption algorithm
 This algorithm generates a unique key specific to MD5 encryption. To decrypt the encrypted text, the MD5 encryption must first be reversed using the provided key. 
 Then, the algorithm attempts to match the hashed value with the wordlist provided by the user to capture a match.
 If a match is found, it displays the plaintext.
