from jsonschema.exceptions import ValidationError, SchemaError
from jsonschema.validators import Draft7Validator
import json
import sys


python, schema_filename, *files = sys.argv


# the validator returns the reference to the rules and data
# as a Deq which doesn't have a useful __str__ or repr
# so we need a helper
def path2str(path):
    """ return a string for the json/schema path """
    pathstr = '.'.join(map(str, path))
    pathstr = f"@ {pathstr}" if pathstr else ""
    return pathstr


with open(schema_filename) as schema_file:
    schema = json.load(schema_file)
    validator = Draft7Validator(schema)

for filename in files:    
        with open(filename) as config_file:
          config_instance = json.load(config_file)

        error_count = 0
        for error_count, error in enumerate(
                sorted(validator.iter_errors(config_instance), key=str), start=1
            ):
            print(
                f"{filename} - #{error_count} - {error.message}"
                f" {path2str(error.path)}\n"
                f"    see {path2str(error.absolute_schema_path)} rule"
                f" in {schema_filename}.\n"
            )

        if not error_count:
            print(f"{filename} validates.")
