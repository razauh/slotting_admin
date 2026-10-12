update player_credential
set password_algo = 'sha256_legacy', password_salt = '', iterations = 0
where password_salt = 'salt' and iterations = 10000;
