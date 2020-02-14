"""
This module adds a new method, get_object_uid to the flask_simpleldap module.

Credit:
    https://github.com/admiralobvious/flask-simpleldap

    Used under MIT license


get_object_uid takes a user DN as the input and returns "fields" specified from the user record. by default it will return the sAMAccountName
"""

import logging
import re
from flask import current_app
from ldap import filter as ldap_filter
import flask_simpleldap
import ldap

logger = logging.getLogger("root")


def get_object_uid(self, user=None, group=None, fields=()):
    """Returns a ``str`` with the object's (user or group) cn field value.
    :param str user: DN of the user object you want the cn for.
    :param str group: DN of the group object you want the cn for.
    """

    # logger.debug("Running method: " + __name__)

    query = None
    if not fields:
        fields = ("sAMAccountName",)
    user_filter = "(&(objectclass=Person)(distinguishedName=%s))"
    group_filter = "(&(objectclass=Group)(distinguishedName=%s))"
    if user is not None:
        query = ldap_filter.filter_format(user_filter, (user,))
    elif group is not None:
        query = ldap_filter.filter_format(group_filter, (group,))
    ldap_connection = self.bind

    # Use ldap connection to perform search
    records = ldap_connection.search_s(
        current_app.config["LDAP_BASE_DN"], ldap.SCOPE_SUBTREE, query, fields
    )

    ldap_connection.unbind_s()
    result = {}
    if records:
        # logger.debug("LDAP result: {0}".format(records))
        for k, v in list(records[0][1].items()):
            # logger.debug("Attribute Key: {0}|Attribute Value: {1}".format(k,v))

            # Check to see if the value is surrounded in quote that might imply that is was returned as byte
            match = re.search("(?<=').*?(?=')", str(v))
            if match:
                try:
                    # try to decode it
                    result = v.decode("utf-8")
                except AttributeError:
                    # revert to just grabbing the text from between the quotes
                    result = match.group(0)
            else:
                result = match
        return result
    else:
        logger.debug("No result")


# Add get_object_uid to LDAP Class
flask_simpleldap.LDAP.get_object_uid = get_object_uid
