# threat-model-scoring-system

This project describes the threat modeling system used by the Open Bitcoin Privacy Project. It includes a set of software tools for expressing threat models, calculating statistics about them, and exporting them to human-readable formats.

By writing a threat model and applying scores to the elements of the threat model, engineers can prioritize security concerns and perform comparative analysis of security between software products, proposed systems, etc.

This system produces threat models that can be generally characterized as "attacker-centric." For more general information about threat modeling, see: [https://en.wikipedia.org/wiki/Threat_model](https://en.wikipedia.org/wiki/Threat_model)

Projects that use this scoring system include:
* [OBPP Bitcoin Wallet Privacy Ratings](https://github.com/OpenBitcoinPrivacyProject/wallet-ratings/)

## Software requirements

* Tested on Python 2.7
* jsonschema `pip install jsonschema`
* hjson if parsing hjson files (optional) `pip install hjson`

## Description of files

* [schema.md](schema.md): This document explains how the scoring system works and is expressed in JSON format.
* [threat model schema.json](threat model schema.json): The JSON schema that defines a threat model.
* [threat model example.json](threat model example.json): An example threat model involving pirates and ghosts.
* [validate.py](validate.py): A script that validates whether an input JSON adheres to an input schema.
* [docgen.py](docgen.py): A script that generates a human-readable files based on an input threat model JSON.
* [weight_comparison.py](weight_comparison.py): A script that takes an old threat model JSON and a new threat model JSON as input and compares scores. The script provides a list of places in the threat model where criteria scores have changed relationships (greater than, equal to, or less than).

## Authors

Open Bitcoin Privacy Project (OBPP)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

* w: http://www.openbitcoinprivacyproject.org/connect/
* e: contact [at] openbitcoinprivacyproject [dot] org
* t: [@obpp_org](https://twitter.com/obpp_org)
