# Define the mitigation measures dictionary
mitigation_measures = {
    'ddos': [
        "Deploy rate limiting to reduce traffic from offending IPs.",
        "Use Anycast to distribute traffic.",
        "Enable Web Application Firewalls (WAF).",
        "Monitor and analyze traffic patterns continuously."
    ],
    'scanning': [
        "Deploy intrusion detection systems to identify scanning patterns.",
        "Block suspicious IPs automatically.",
        "Implement honeypots to mislead attackers.",
        "Ensure critical systems are segmented from open networks."
    ],
    'password': [
        "Enforce strong password policies (e.g., length, complexity).",
        "Enable multi-factor authentication (MFA).",
        "Monitor login attempts for brute force patterns.",
        "Secure password storage with hashing and salting."
    ],
    'benign': [
        "No action needed. Normal traffic detected."
    ]
}

# Modify the function to normalize the attack type
def get_mitigation_for_attack(class_name):
    mitigation_measures = {
        'ddos': [
            "Deploy rate limiting to reduce traffic from offending IPs.",
            "Use Anycast to distribute traffic.",
            "Enable Web Application Firewalls (WAF).",
            "Monitor and analyze traffic patterns continuously."
        ],
        'scanning': [
            "Deploy intrusion detection systems to identify scanning patterns.",
            "Block suspicious IPs automatically.",
            "Implement honeypots to mislead attackers.",
            "Ensure critical systems are segmented from open networks."
        ],
        'password': [
            "Enforce strong password policies (e.g., length, complexity).",
            "Enable multi-factor authentication (MFA).",
            "Monitor login attempts for brute force patterns.",
            "Secure password storage with hashing and salting."
        ],
        'benign': [
            "No action needed. Normal traffic detected."
        ]
    }

    # Normalize the class_name to match the dictionary keys (uppercase)
    class_name = class_name.strip().lower()

    # Fetch mitigation measures based on the normalized attack type
    attack_mitigation = mitigation_measures.get(class_name, [
        "No specific mitigation defined for this attack type.",
        "General recommendations:",
        "- Regularly monitor and analyze traffic patterns.",
        "- Enable intrusion detection and prevention systems.",
        "- Conduct regular security audits."
    ])

    return attack_mitigation
