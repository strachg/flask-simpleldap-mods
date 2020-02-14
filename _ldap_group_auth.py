"""
This module adds a new method, basic_group_auth_required to the flask_simpleldap module.

Credit:
    https://github.com/admiralobvious/flask-simpleldap

    Used under MIT license
"""

from flask import Flask, abort, current_app, g, make_response, request
import flask_simpleldap
import logging
import re

logger = logging.getLogger("root")


def basic_group_auth_required(self, groups=None):
    """When applied to a view function, any unauthenticated requests are
    asked to authenticate via HTTP's standard Basic Authentication system.
    Requests with credentials are checked with :meth:`.bind_user()`.
    The user's browser will typically show them the contents of
    LDAP_REALM_NAME as a prompt for which username and password to enter.
    If the request's credentials are accepted by the LDAP server and they
    are a member of one of the matching groups, the username is stored in ``flask.g.ldap_username``, the password in
    ``flask.g.ldap_password`` and the matching groups in ``flask.g.ldap_user_groups```.
    :param groups: A list of groups that any authenticating user must be a member of.

    """
    # logger.debug("Running method: " + __name__)

    def make_auth_required_response():
        response = make_response("Unauthorized", 401)
        response.www_authenticate.set_basic(current_app.config["LDAP_REALM_NAME"])
        return response

    def wrapper(func):
        # @wraps(func)
        def wrapped(*args, **kwargs):
            if request.authorization is None:
                req_username = None
                req_password = None
            else:
                req_username = request.authorization.username
                req_password = request.authorization.password

            # Many LDAP servers will grant you anonymous access if you log in
            # with an empty password, even if you supply a non-anonymous user
            # ID, causing .bind_user() to return True. Therefore, only accept
            # non-empty passwords.
            if req_username in ["", None] or req_password in ["", None]:
                logger.debug("Got a request without auth data")
                return make_auth_required_response()

            if not self.bind_user(req_username, req_password):
                logger.debug("User {0!r} gave wrong " "password".format(req_username))
                return make_auth_required_response()

            g.ldap_username = req_username
            g.ldap_password = req_password

            auth_user = g.ldap_username
            users = []
            user_groups = []
            logger.debug("Login User: {0}".format(g.ldap_username))
            for group in groups:
                # logger.debug('Group : {0}'.format(group))
                try:
                    group_members = self.get_group_members(group)
                    # logger.debug('Group Members: {0}'.format(group_members))
                except:
                    # logger.debug('Group Members: {0}'.format(group_members))
                    return make_auth_required_response()
                try:
                    for group_member in group_members:
                        user_uid = self.get_object_uid(user=group_member)
                        # logger.debug('Member UserID: {0}'.format(user_uid))
                        match = auth_user == user_uid
                        if match:
                            users.append(user_uid)
                            user_groups.append(str(group))
                except Exception:
                    logger.debug(
                        "Group {0} has no matching members - {1}".format(
                            group, auth_user
                        )
                    )
                    next

            # If no matches are found response with "Unauthorized"
            if len(users) < 1:
                return make_auth_required_response()
            else:
                logger.debug("Match Group(s): {0}".format(str(user_groups)))
                g.ldap_user_groups = user_groups
                return func(*args, **kwargs)

        wrapped.__name__ = func.__name__
        return wrapped

    return wrapper


# Add basic_group_auth_required to LDAP Class
flask_simpleldap.LDAP.basic_group_auth_required = basic_group_auth_required
