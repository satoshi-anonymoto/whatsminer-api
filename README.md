# whatsminer-api
Unofficial python api for MicroBT Whatsminer ASICs
---
_Code adapted from a python file found in the Whatsminer Telegram group that is credited to `@passby`_


## Installation
Python 3.x is required.

```
pip install whatsminer
```


## Basic Usage
Instantiate a `WhatsminerAccessToken` for each ASIC that you want to access. Then make read-only or writeable API calls through `WhatsminerAPI`

Read-only information can be retrieved with just the ASIC's ip address:

```python
from whatsminer import WhatsminerAccessToken, WhatsminerAPI

token = WhatsminerAccessToken(ip_address="192.168.1.100")
summary_json = WhatsminerAPI.get_read_only_info(access_token=token, cmd="summary")
```

The writeable API commands can be executed by providing the ASIC's admin password:

```python
# The token from above can be enabled for writeable access:
token.enable_write_access(admin_password="the_admin_password")

# Or you can directly instantiate a writeable one:
token = WhatsminerAccessToken(ip_address="192.168.1.100", admin_password="the_admin_passwd")

json_response = WhatsminerAPI.exec_command(access_token, cmd="power_off", additional_params={"respbefore": "true"})
```

Writeable `WhatsminerAccessToken` objs will renew themselves if they go past the API's 30min expiration.


### Managing multiple ASICs
You could define a whole server farm's worth of Whatsminer ASICs and manage them all in one script:

```python
asics = [
    ('192.168.1.100', 'some_admin_pass'),
    ('192.168.1.101', 'some_admin_pass'),
    ('192.168.1.102', 'some_admin_pass'),
    ('192.168.1.103', 'some_admin_pass'),
    ('192.168.1.104', 'some_admin_pass'),
    ('192.168.1.105', 'some_admin_pass'),
]
tokens = []
for asic_info in asics:
    tokens.append(WhatsminerAccessToken(ip_address=asic_info[0], admin_password=asic_info[1]))

# Find machines running too hot
for token in tokens:
    json_summary = WhatsminerAPI.get_read_only_info(token, cmd="summary")
    if json_summary['SUMMARY'][0]['Temperature'] > 78.0:
        # stop mining on this ASIC
        WhatsminerAPI.exec_command(access_token, cmd="power_off", additional_params={"respbefore": "true"})
```


## API Documentation
It's very difficult to find any information about the Whatsminer API. This PDF documentation is slightly out of date but is the best source found so far:

[WhatsminerAPIV1.3.8.pdf](docs/WhatsminerAPIV1.3.8.pdf)


## Package distribution notes
_There are just notes to self for updating the pypi distribution_
* Update the release number in `setup.py` and commit to repo.
* Draft a new release in github using the same release number.
* Run `python setup.py sdist`
* Publish the distribution to pypi: `twine upload dist/*`

