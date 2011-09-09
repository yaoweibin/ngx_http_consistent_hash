#
#===============================================================================
#
#         FILE:  sample.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the first time request
--- http_config
    upstream test{      
        server www.ruby-lang.org:82;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_connect_timeout 3s;
        proxy_pass http://test;
    }
--- more_headers
Host: www.nginx.org
--- request
GET /
--- response_headers_like
Server: nginx.*

