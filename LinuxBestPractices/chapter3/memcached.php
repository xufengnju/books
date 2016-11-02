<?php

function generateRandomString($length = 10) {
    $characters       = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString     = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

$servers = array(
    array(
        '10.1.6.28',
        11211
    ),
    array(
        '10.1.6.38',
        11211
    ),
    array(
        '10.1.6.44',
        11211
    )
);

$m = new Memcached();
$m->setOption(Memcached::OPT_DISTRIBUTION, Memcached::DISTRIBUTION_CONSISTENT);
$m->setOption(Memcached::OPT_LIBKETAMA_COMPATIBLE, true);
$m->addServers($servers);

$count = 0;
while ($count < 10000) {
    $m->set(generateRandomString(), 1);
    $count++;
}

?>