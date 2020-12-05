import hashlib
import secrets
from mailconfig import open_database

# public representation of an api key that can be displayed in the control panel
KEY_INFO_FIELDS = "id, label, scopes, created_at, expires_in, mru"


def to_key_info_dict(r):
    return {
        "id": r[0],
        "label": r[1],
        "scopes": r[2],
        "created_at": r[3],
        "expires_in": r[4],
        "mru": r[5],
    }


# private representation of an api key that can be used in the auth flow
KEY_CREDENTIAL_FIELDS = "id, user_id, key_hash, scopes, expires_in, mru"


def to_key_credential_dict(r):
    return {
        "id": r[0],
        "user_id": r[1],
        "key_hash": r[2],
        "scopes": r[3],
        "expires_in": r[4],
        "mru": r[5],
    }


def get_user_id(email, c):
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    r = c.fetchone()
    if not r:
        raise ValueError("User does not exist.")
    return r[0]


def create_api_key(email, label, scopes, env):
    conn, c = open_database(env, with_connection=True)
    user_id = get_user_id(email, c)

    key = secrets.token_urlsafe(40)
    key_hash = hashlib.new("sha256", key.encode()).hexdigest()

    c.execute(
        "INSERT INTO api_keys(user_id, key_hash, label, scopes) VALUES (?, ?, ?, ?)",
        (user_id, key_hash, label, scopes),
    )
    # sqlite lacks a `RETURNING` clause, we can use `cursor.lastrowid` to pull key we just created from the db
    r = c.execute(
        "SELECT {f} FROM api_keys WHERE id=?".format(f=KEY_INFO_FIELDS), (c.lastrowid,)
    )
    conn.commit()

    return {
        "api_key": to_key_info_dict(r.fetchone()),
        "key": key,
    }


def remove_api_key(email, key_id, env):
    conn, c = open_database(env, with_connection=True)
    user_id = get_user_id(email, c)
    c.execute("DELETE FROM api_keys WHERE user_id=? AND id=?", (user_id, key_id))
    conn.commit()


def get_api_key_infos(email, env):
    c = open_database(env)
    c.execute(
        "SELECT {f} FROM api_keys WHERE user_id=?".format(f=KEY_INFO_FIELDS),
        (get_user_id(email, c),),
    )
    return [to_key_info_dict(r) for r in c.fetchall()]


def get_api_key_credentials(email, env):
    c = open_database(env)
    c.execute(
        "SELECT {f} FROM api_keys WHERE user_id=?".format(f=KEY_CREDENTIAL_FIELDS),
        (get_user_id(email, c),),
    )
    return [to_key_credential_dict(r) for r in c.fetchall()]
