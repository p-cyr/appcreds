(openstack) pjcyr@CBR-224C2T2:~$ python appcreds.py create --cloud openstack --name cicd-token --roles member,reader --expires-in 90d --description "CICD token"
/home/pjcyr/appcreds.py:48: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  expires = (dt.datetime.utcnow() + delta).replace(microsecond=0)
{
  "id": "39e7eb9292d8406092f659bd88a57c73",
  "name": "cicd-token",
  "description": "CICD token",
  "project_id": "d43336de8993452286714bdd3251581a",
  "user_id": "d19c2c14530d46e78ac4494ef7ed7ecc",
  "expires_at": "2026-05-13T16:23:18.000000",
  "secret": "the_secret",
  "roles": [
    {
      "name": "member"
    },
    {
      "name": "reader"
    }
  ],
  "unrestricted": false,
  "access_rules": []
}

Secret is shown only once!
(openstack) pjcyr@CBR-224C2T2:~$ python appcreds.py delete --cloud openstack --name cicd-token
Deleted credential id=39e7eb9292d8406092f659bd88a57c73 name=cicd-token