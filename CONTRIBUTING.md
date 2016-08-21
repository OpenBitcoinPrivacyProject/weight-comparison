# Making changes to JSON files

Before making a pull request that changes JSON files included in this project, you SHOULD run the two following commands:

    $ python validate_json.py [name-of-your-json-file]

    $ python docgen.py [name-of-your-json-file]

This will ensure that you have not introduced any errors in your changes to the JSON, and that all changes are reflected in generated documents.

# Making changes to Python files
Before making a pull requests that changes any Python source code files, you SHOULD run it against `pylint`. When possible, you should avoid lowering the `pylint` score of files you modify.
