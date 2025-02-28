minimum_required_fields = ("type", "uuid", "value")

checking_error = 'containing at least a "type" field and a "value" field'
standard_error_message = 'This module requires an "attribute" field as input'


def check_input_attribute(attribute, requirements=minimum_required_fields):
    return all(feature in attribute for feature in requirements)
