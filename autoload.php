<?php
/**
 * Created by IntelliJ IDEA.
 * User: rek
 * Date: 15/4/23
 * Time: 下午6:04
 */

spl_autoload_register(function($class) {
    if (DIRECTORY_SEPARATOR !== '\\') {
        $class = str_replace('\\', DIRECTORY_SEPARATOR, $class);
    }
    $path = __DIR__;
    if ($class[0] !== DIRECTORY_SEPARATOR)
        $path .= DIRECTORY_SEPARATOR;
    $file = "$path$class.php";
    if (is_file($file)) {
        include_once($file);
    }
});