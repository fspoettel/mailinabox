import hashlib
import secrets
from mailconfig import open_database

KEY_INFO_FIELDS = "id, label, scopes, created_at, expires_in"


def to_key_info_dict(r):
    return {
        "id": r[0],
        "label": r[1],
        "scopes": r[2],
        "created_at": r[3],
        "expires_in": r[4],
    }


def get_user_id(email, c):
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    r = c.fetchone()
    if not r:
        raise ValueError("User does not exist.")
    return r[0]


def get_api_keys(email, env):
    c = open_database(env)
    c.execute(
        "SELECT {f} FROM api_keys WHERE user_id=?".format(f=KEY_INFO_FIELDS),
        (get_user_id(email, c),),
    )
    return [to_key_info_dict(r) for r in c.fetchall()]


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
