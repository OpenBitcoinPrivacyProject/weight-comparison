## Description

Threat model authors can use this system to specify their threat models in JSON format.

In order to understand our system’s schema, please refer to the [threat model example.json](threat model example.json) provided. This is a silly threat model based on relative threats of two kinds of enemies in a game, as well as the relative defensive strength of players who employ different countermeasures.


## The schema

There are four important entities to consider in our threat model schema:

* **Attackers**: The actors who attack the defender
* **Attacks**: Actions performed by attackers to compromise the defender’s security
* **Countermeasures**: Actions performed by the defender to partially or wholly mitigate attacks
* **Criteria**: Observable qualities of the defender that partially or wholly satisfy a countermeasure

Attackers and attacks are weighted relative to their siblings. See the `weight` attribute.

Countermeasures and criteria may apply to multiple attacker/attack categories, and so are listed separately with pointers to them using their “id” attribute. Countermeasures are given an “effectiveness” score between 0% and 100% in terms of how well they mitigate an attack. Criteria are given a similar score in terms of well they satisfy a countermeasure.

Criteria may have varying relationships with each other and their satisfaction of countermeasures, so they are separated into “criteria-groups”.

**Terminology:**
* Two criteria at the same level in the same criteria group are “_sibling criteria_”
* Two criteria at the same level but belong to different criteria group are “_cousin criteria_”

_Sibling criteria_ have an additive relationship. If a defender satisfies two sibling criteria, his score represents the sum of the two up to a maximum of 100%. This relationship generally describe criteria that can be satisfied simultaneously and/or which have a cumulative effect. In our example JSON, against a ninja punch attack, a player may can both cross his arms in front of him (`NINJAGHOSTV1-CR2`) and assume the fetal position (`NINJAGHOSTV1-CR3`), and both will help a little bit against the ninja’s punch.

_Cousin criteria_ have a non-additive relationship. If a defender satisfies two cousin criteria, his score represents the maximum of the two. This relationship generally describes criteria with exclusive satisfiability, or which have no cumulative effect. In our example JSON, against a ninja punch, a player may completely evade the punch (`NINJAGHOSTV1-CR1`) or assume the fetal position (`NINJAGHOSTV1-CR3`), but can’t do both.
