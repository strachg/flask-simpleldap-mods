"""
This module is used to update a method from the flask_simpleldap module.

Original:
    conn.simple_bind_s(user_dn.decode('utf-8'), password)
Update:
    conn.simple_bind_s(str(user_dn), password)

Credit:
    https://github.com/admiralobvious/flask-simpleldap

    Used under MIT license
"""
import ldap
import flask_simpleldap


def new_bind_user(self, username, password):
    """Attempts to bind a user to the LDAP server using the credentials
    supplied.
    .. note::
        Many LDAP servers will grant anonymous access if ``password`` is
        the empty string, causing this method to return :obj:`True` no
        matter what username is given. If you want to use this method to
        validate a username and password, rather than actually connecting
        to the LDAP server as a particular user, make sure ``password`` is
        not empty.
    :param str username: The username to attempt to bind with.
    :param str password: The password of the username we're attempting to
        bind with.
    :return: Returns ``True`` if successful or ``None`` if the credentials
        are invalid.
    """
    # logger.debug("Running method: " + __name__)

    try:
        user_dn = self.get_object_details(user=username, dn_only=True)
    except flask_simpleldap.LDAPException:
        return

    if user_dn is None:
        return
    try:
        conn = self.initialize
        conn.simple_bind_s(str(user_dn), password)
        # Original:
        # conn.simple_bind_s(user_dn.decode('utf-8'), password)
        return True
    except ldap.LDAPError:
        return


# Update bind_user with new_bind_user in LDAP Class
flask_simpleldap.LDAP.bind_user = new_bind_user
