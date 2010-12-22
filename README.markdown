About
=====

rlm_backcounter manages various counters which count back and are periodically
resetted to some value. These counters can be defined eg. for whole user group,
but with values and reset intervals specific for each individual user.

There is also additional "prepaid" counter, which can be set to any value from
outside of rlm_backcounter - the module only decreases it.

This module can be used to e.g.

  * limit monthly bandwidth usage, with uniform distribution of counter resets
    during month (ie. to overcome excessive network usage when all users have
    their counters resetted on the same day),
  * implement prepaid accounts,
  * put your clients' network traffic into various QoS/SLA classes depending on
    their network usage.

How it works
============

Authorization
-------------

_Note_: Why to do anything related to counters in this section? Because it's far
more easier in FreeRADIUS to react as soon as possible, and to do user updates,
etc. basing on attributes in request packets (instead of reply packets).

* if the counter of the user we're handling request for should be resetted:
    * set the counter to the value defined in user's reply attributes
      (fetched from database), or if these don't exist, in group's reply
      attributes
    * set reset time to current value + period defined in module
      instance-wide configuration, making sure it's greater than current
      time moment
* fetch current counter values and check if their sum is greater than
  zero:
    * if user is under limit, set session "guard VAP" to the counter
      value (if configured to do so)
    * otherwise, add a new VAP to the request packet or simply send back
      an access rejection

Accounting
----------

Only _Accounting-Stop_ packets are considered.

* decrease counters in configurable manner:
     * use sum of values in VAPs given in configuration as the decrement
     * let the administrator choose whether to decrement the prepaid or the
       "monthly" counter first

Installation
============

1. Download and unpack FreeRADIUS - e.g. to *freeradius/*
2. Put source code of this module in *freeradius/src/modules/rlm_backcounter/*
3. Add "rlm_backcounter" at the top of *freeradius/src/modules/stable* file
4. Change directory into *freeradius/src/modules/rlm_backcounter/*
5. Run *autoconf* (you may need to install it on your system)
6. Proceed with the standard FreeRADIUS installation procedure.
7. Verify if you have a file named *rlm_backcounter.so* in your libraries
   (usually /usr/lib or /usr/local/lib).

Configuration
=============

An example on how to create a monthly transfer limit.

In radiusd.conf, create module configuration:

    modules {
        # (...)

        backcounter transfer-limit {
            # name of rlm_sql module instance to connect to
            sqlinst_name = "sql"

            # what to count in accounting packets
            count_names = "Acct-Input-Octets, Acct-Output-Octets"

            # VAP in which to send the amount which is left
            guardvap = "Session-Octets-Limit"
            #guardvap = "Mikrotik-Total-Limit"

            # VAP to use if the value in guardvap is greater than 2^32
            # it will hold the bits 32-63 of the number
            #giga_guardvap = "Mikrotik-Total-Limit-Gigawords"

            # reset counters each 30 days
            period = 2592000

            # monthly transfer limit, in bytes
            limitvap = "Monthly-Transfer-Limit"

            # if enabled, the counters will not be resetted
            #noreset = "yes"

            # time of next reset for this particular user
            resetvap = "Monthly-Transfer-Reset"

            # VAP to set in *request* to 1 if the user has reached his limits
            overvap = "Monthly-Transfer-Exceeded"

            # transfer left - monthly, prepaid
            leftvap = "Monthly-Transfer-Left"
            prepaidvap = "Monthly-Transfer-Prepaid"

            # which counter to decrease first
            prepaidfirst = yes
        }
    }

Then, instantiate it after rlm_sql:

    instantiate {
        # (...)
        sql
        transfer-limit
        # (...)
    }

Put it in the authorize section after rlm_sql:

    authorize {
        # (...)
        sql
        transfer-limit
        # some module to restrict bandwidth if overvap is set, eg.:
        # users
        # (...)
    }

And anywhere in the accounting section:

    accounting {
        # (...)
        transfer-limit
    }

Add new attributes in the dictionary file:

    # (...)

    # custom, local attributes that will not get sent over the network
    ATTRIBUTE Monthly-Transfer-Limit    3100 string
    ATTRIBUTE Monthly-Transfer-Reset    3101 integer
    ATTRIBUTE Monthly-Transfer-Exceeded 3102 integer
    ATTRIBUTE Monthly-Transfer-Left     3103 string
    ATTRIBUTE Monthly-Transfer-Prepaid  3104 string

    # a session traffic limit for pppd
    # for some reason it's not in the official FreeRADIUS dictionary
    ATTRIBUTE Session-Octets-Limit       227 integer

    # Mikrotik session traffic limits
    ATTRIBUTE Mikrotik-Total-Limit                    17      integer
    ATTRIBUTE Mikrotik-Total-Limit-Gigawords          18      integer

If you wish to limit bandwidth usage on eg. a Lintrack router, add this to your
users file (some modifications depending on local configuration may be
required):

    DEFAULT Monthly-Transfer-Exceeded == 1
        Reply-Message = "You have reached your monthly bandwidth limit",
        ASN-Kbps-Down := 64,
        ASN-Kbps-Up := 64

Levels
======

Version 0.2 brings a feature of counter rates dependent on time - for example it
can count two times slower during weekends. This functionality is configured
using *levels* keyword.

Example: Lets say that today just after midnight the UNIX timestamp was
1279670400. Its a time reference point. You want to make a special level which
repeats each week = 7 days = 168 hours = 604800 seconds. You want to count half
data from midnight till 6.00 AM = 6 hours = 21600 seconds. So in radiusd.conf
you'll write:

    levels = "from 1279670400 each 604800 for 21600 use 0.5"

If you want to implement your "half data is counted at evenings and weekends",
you write:

    levels = "from 1279753200 each 86400 for 21600 use 0.5,   \
              from 1279947600 each 604800 for 172800 use 0.5"

If you have at least one level defined, the server will automatically set
*Session-Timeout* VAP to the closest level change event minus 15 seconds. The
server will also ensure that the *Session-Timeout* is not set to a value smaller
than 60 seconds.

Levels are used in the order they appear in config file. First matching level
wins.

Current limitations (maybe a TODO list)
=======================================

* probably works only with MySQL
* a bit too "hardcoded"
    * queries and table names not configurable
    * low-level access to database
