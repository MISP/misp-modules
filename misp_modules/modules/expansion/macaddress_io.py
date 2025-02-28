import json

from maclookup import ApiClient, exceptions

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["mac-address"],
}

moduleinfo = {
    "version": "1.0",
    "author": "CodeLine OY - macaddress.io",
    "description": "MISP hover module for macaddress.io",
    "module-type": ["hover"],
    "name": "Macaddress.io Lookup",
    "logo": "macaddress_io.png",
    "requirements": [
        "maclookup: macaddress.io python library",
        "An access to the macaddress.io API (apikey)",
    ],
    "features": (
        "This module takes a MAC address attribute as input and queries macaddress.io for additional"
        " information.\n\nThis information contains data about:\n- MAC address details\n- Vendor details\n- Block"
        " details"
    ),
    "references": [
        "https://macaddress.io/",
        "https://github.com/CodeLineFi/maclookup-python",
    ],
    "input": "MAC address MISP attribute.",
    "output": "Text containing information on the MAC address fetched from a query on macaddress.io.",
}

moduleconfig = ["api_key"]


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if request.get("mac-address"):
        mac_address = request["mac-address"]
    else:
        return False

    if request.get("config") and request["config"].get("api_key"):
        api_key = request["config"].get("api_key")
    else:
        misperrors["error"] = "Authorization required"
        return misperrors

    api_client = ApiClient(api_key)

    try:
        response = api_client.get(mac_address)

    except exceptions.EmptyResponseException:
        misperrors["error"] = "Empty response"
        return misperrors

    except exceptions.UnparsableResponseException:
        misperrors["error"] = "Unparsable response"
        return misperrors

    except exceptions.ServerErrorException:
        misperrors["error"] = "Internal server error"
        return misperrors

    except exceptions.UnknownOutputFormatException:
        misperrors["error"] = "Unknown output"
        return misperrors

    except exceptions.AuthorizationRequiredException:
        misperrors["error"] = "Authorization required"
        return misperrors

    except exceptions.AccessDeniedException:
        misperrors["error"] = "Access denied"
        return misperrors

    except exceptions.InvalidMacOrOuiException:
        misperrors["error"] = "Invalid MAC or OUI"
        return misperrors

    except exceptions.NotEnoughCreditsException:
        misperrors["error"] = "Not enough credits"
        return misperrors

    except Exception:
        misperrors["error"] = "Unknown error"
        return misperrors

    date_created = (
        response.block_details.date_created.strftime("%d %B %Y") if response.block_details.date_created else None
    )

    date_updated = (
        response.block_details.date_updated.strftime("%d %B %Y") if response.block_details.date_updated else None
    )

    results = {
        "results": [
            {
                "types": ["text"],
                "values": {
                    # Mac address details
                    "Valid MAC address": "True" if response.mac_address_details.is_valid else "False",
                    "Transmission type": response.mac_address_details.transmission_type,
                    "Administration type": response.mac_address_details.administration_type,
                    # Vendor details
                    "OUI": response.vendor_details.oui,
                    "Vendor details are hidden": "True" if response.vendor_details.is_private else "False",
                    "Company name": response.vendor_details.company_name,
                    "Company's address": response.vendor_details.company_address,
                    "County code": response.vendor_details.country_code,
                    # Block details
                    "Block found": "True" if response.block_details.block_found else "False",
                    "The left border of the range": response.block_details.border_left,
                    "The right border of the range": response.block_details.border_right,
                    "The total number of MAC addresses in this range": response.block_details.block_size,
                    "Assignment block size": response.block_details.assignment_block_size,
                    "Date when the range was allocated": date_created,
                    "Date when the range was last updated": date_updated,
                },
            }
        ]
    }

    return results


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
