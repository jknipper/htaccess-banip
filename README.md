Apache htaccess ban IP script
=============================

This script blocks IP addresses in Apache .htaccess file after a certain amount of failed logins (401 errors).

Installation
------------

Just copy the banip folder in your webroot and add the following line to your .htaccess file:

    ErrorDocument 401 /banip/banip.php

See head of banip.php for max login retries and find time. The script appends "DENY FROM IP-address" to your htaccess file. [AllowOverride](http://httpd.apache.org/docs/2.2/en/mod/core.html#allowoverride) must be set accordingly in your virtual host configuration.

License
-------

The MIT License (MIT)

Copyright (c) 2015 Jan Knipper <j.knipper@part.berlin>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.