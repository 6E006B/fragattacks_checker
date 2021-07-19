## fragattacks_checker

Convenience script to check all / multiple fragattacks vulnerabilities.

Relies on the `fragattack.py` script from https://github.com/vanhoefm/fragattacks.
The path to the script needs to be set with `-s` if it is not in the same directory.

For information on the setup of `fragattack.py` refer to https://github.com/vanhoefm/fragattacks/blob/master/README.md.

All credit is due to Mathy Vanhoef, go to https://www.fragattacks.com/ to learn more.

### usage

```
Wrapper script for fragattack.py to execute all checks in batch.
Remember to call from the appropriate env, i.e. root and activated venv.

       [-h] [-s SCRIPT] [-v] [-n] [-r RETRIES] interface

positional arguments:
  interface             interface to use for checks

optional arguments:
  -h, --help            show this help message and exit
  -s SCRIPT, --script SCRIPT
                        fragattacks script (default: ./fragattack.py)
  -v, --verbose
  -n, --no-mixed-keys   skip the mixed key attacks, which might hang during execution
  -r RETRIES, --retries RETRIES
                        number of retries if retry is suggested by script for assurance
```
