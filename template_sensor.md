**Template Sensor - Last Person**

A helper template sensor can help to identify the last person accessing by the keypad.
This sensor needs to be updated whenever you add a new pin, face, palm, fingerprint or nfc card. 
The index is counted from the bottom inside the Switchbot App and starts with index 0.


HomeAssistant -> Settings -> Devices&Services -> Helpers -> Template -> Sensor


```
{% set method = states('sensor.switchbot_keypad_bridge_method') | lower %}
          {% set idx = states('sensor.switchbot_keypad_bridge_index') | int(-1) %}

          {# Mapping: Methode -> { Index: "Person" } #}
          {% set users = {
            'pin': {
              0: 'Steffen',
              1: 'Notfallcode',
              2: 'Sandra',
            },
            'face': {
              0: 'Steffen',
              1: 'Steffen',
              2: 'Sandra',
              3: 'Steffen',
              4: 'Sandra',
              5: 'Andy',
            },
            'palm': {
              0: 'Steffen',
              1: 'Sandra',
              2: 'Uschi',
              3: 'Michael H.',
              4: 'Andy',
              5: 'Hannah',
            },
            'fingerprint': {
              0: 'Steffen',
              1: 'Sandra',
              2: 'Sandra',
              3: 'Jakob',
              4: 'Uschi',
              5: 'Michael H.',
              6: 'Michael L.',
              7: 'Christiane',
              8: 'Andy',
              9: 'Sarah',
              10: 'Hannah',
              11: 'Philipp',
            },
            'nfc': {
            }
          } %}

          {% if method in users and idx in users[method] %}
            {{ users[method][idx] }}
          {% elif method in ['unknown', 'unavailable', 'none', ''] or idx == -1 %}
            Unknown
          {% else %}
            Unknown ({{ method }} #{{ idx }})
          {% endif %}
```
