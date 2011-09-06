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

=== TEST 1: the first time request, hit apache
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.ruby-lang.org
--- request
GET /
--- response_headers_like
Server: Apache.*

=== TEST 2: the second time request, hit apache 
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.ruby-lang.org
--- request
GET /en/download.html
--- error_code: 404
--- response_headers_like
Server: Apache.*

=== TEST 3: the third time request, hit Apache
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.ruby-lang.org
--- request
GET /en/security_advisories.html
--- error_code: 404
--- response_headers_like
Server: Apache.*

=== TEST 4: the forth time request, hit Apache
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.nginx.org
--- request
GET /en/documentation/
--- error_code: 404
--- response_headers_like
Server: Apache.*

=== TEST 5: the first time request, hit nginx 
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.nginx.org
--- request
GET /en/security/
--- error_code: 404
--- response_headers_like
Server: nginx.*

=== TEST 6: the second time request, hit nginx
--- http_config
    upstream test{      
        server www.ruby-lang.org;
        server www.nginx.org;

        consistent_hash $request_uri;
    }

--- config
    location / {
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_pass http://test;
    }
--- more_headers
Host: www.nginx.org
--- request
GET /en/documentation/quickstart/
--- error_code: 404
--- response_headers_like
Server: nginx.*

