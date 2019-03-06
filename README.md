## Prevent CSRF with nginx

This is a simple nginx module which compares either the referer or the origin header to the host header. If the domain name doesn't match, HTTP response 403 is returned. This action takes place before the request is processed and will terminate any additional processing. If the request lacks both a referer and a origin header, no action will be taken.

To activate this check, place `csrf_prevent on;` in the block you wish to protect. You can put it in the `server`, `location`, or `if`  blocks. If activated in a parent block, all child blocks will also be protected. You can disable the check for a specific block with `csrf_prevent off;`.

## Examples

Apply to all requests

```
location / {
	csrf_prevent on;
	proxy_pass http://localhost:5000/;
}
```

Only apply to POST:

```
location / {
	if ($request_method = POST)
	{
		csrf_prevent on;
	}
	proxy_pass http://localhost:5000/;
}
```

## Installation

In order to install a nginx module, you'll have to compile nginx from source. Download the source from https://nginx.org/en/download.html. You'll also need to clone this repo. Inside the nginx source directory run `./configure --add-module=/path/to/my-module`. If you have nginx currently installed, you can get the existing configure options with `nginx -V`. It's annoying that you have to recompile nginx to add a module, but I don't have any other way.
To build for nginx-plus, use `./configure --with-compat --add-dynamic-module=/path/to/my-module`.
