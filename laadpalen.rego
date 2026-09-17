package authz

import rego.v1

# Laadpalen example policy.
#
# request_laadpaal(resource_context={"postcode": ..., "huisnummer": ...},
# identity_context=<requester>) returns an AuthZEN-shaped Decision object:
# {"decision": bool, "context": {"reason": string}} - "decision" and
# "context" are the spec's normative fields (openid.github.io/authzen,
# section 5.5); "reason" is only a convention for a key inside "context",
# not a top-level field.
#
# Decision order (first matching reason wins):
#   1. postcode/huisnummer not in the fixed address list
#   2. requester not personally eligible for either track (wrong department /
#      no diploma / expired diploma)
#   3. requester's eligible track doesn't match the address's track
#      (citizen-only requester at a diplomatic address, or vice versa)
#   4. address already has a laadpaal
#   5. address has no electric vehicle
#   6. otherwise: toegekend
#
# A course carries a `validity` property (an ISO-8601 duration, e.g. "P1Y");
# a diploma carries a `last_test_date` (RFC3339). A diploma is valid while
# now() < last_test_date + validity.
#
# NOTE: only whole-year durations ("P<N>Y") are parsed - that's the only form
# the laadpalen-management course actually uses, this is not a general
# ISO-8601 duration parser.

default request_laadpaal := {"decision": false, "context": {"reason": "Onbekende fout"}}

request_laadpaal := result if {
        not adres_bestaat(input.resource.postcode, input.resource.huisnummer)
        result := {"decision": false, "context": {"reason": "Postcode/huisnummer niet gevonden"}}
} else := result if {
        result := {"decision": false, "context": {"reason": eligibility_failure}}
} else := result if {
        adres_diplomatiek(input.resource.postcode, input.resource.huisnummer)
        not is_department_member("bestuursbureau")
        result := {"decision": false, "context": {"reason": "Niet toegekend vanwege diplomatiek kenteken"}}
} else := result if {
        not adres_diplomatiek(input.resource.postcode, input.resource.huisnummer)
        not is_department_member("burgerzaken")
        result := {"decision": false, "context": {"reason": "Niet toegekend vanwege ontbrekend diplomatiek kenteken op adres"}}
} else := result if {
        adres_laadpaal_aanwezig(input.resource.postcode, input.resource.huisnummer)
        result := {"decision": false, "context": {"reason": "Reeds laadpaal aanwezig"}}
} else := result if {
        not adres_elektrisch_voertuig(input.resource.postcode, input.resource.huisnummer)
        result := {"decision": false, "context": {"reason": "Geen elektrisch voertuig gevonden op adres"}}
} else := {"decision": true, "context": {"reason": "Toegekend"}}

# personal eligibility, independent of address: the reason the requester has
# no usable track at all, or undefined if they qualify for at least one.
eligibility_failure := reason if {
        not is_department_member("burgerzaken")
        not is_department_member("bestuursbureau")
        reason := "Niet geautoriseerd vanwege afdeling"
} else := reason if {
        not has_any_diploma("laadpalen-management")
        reason := "Niet geautoriseerd vanwege opleiding"
} else := reason if {
        not has_valid_diploma("laadpalen-management")
        reason := "Niet geautoriseerd vanwege verlopen opleiding"
}

is_department_member(department) if {
        ds.check({
                "object_type": "department",
                "object_id": department,
                "relation": "member",
                "subject_type": "user",
                "subject_id": input.user.id,
        })
}

# diploma ids for course_id that the requester actually holds.
users_diploma_ids(course_id) := {diploma_id |
        some diploma_id in diploma_ids_for_course(course_id)
        ds.check({
                "object_type": "diploma",
                "object_id": diploma_id,
                "relation": "holder",
                "subject_type": "user",
                "subject_id": input.user.id,
        })
}

has_any_diploma(course_id) if {
        count(users_diploma_ids(course_id)) > 0
}

has_valid_diploma(course_id) if {
        some diploma_id in users_diploma_ids(course_id)
        diploma_valid(diploma_id, course_id)
}

# every diploma object issued for the given course.
diploma_ids_for_course(course_id) := {rel.object_id |
        some rel in ds.relations({
                "object_type": "diploma",
                "relation": "course",
                "subject_type": "course",
                "subject_id": course_id,
        }).results
}

# fail-safe: if the diploma/course properties are missing or malformed, the
# diploma is *not* considered valid (default wins over an undefined body,
# unlike `not diploma_expired(...)` which would wrongly succeed on missing data).
default diploma_valid(_, _) = false

diploma_valid(diploma_id, course_id) = true if {
        last_test_date := ds.object({"object_type": "diploma", "object_id": diploma_id}).properties.last_test_date
        validity := ds.object({"object_type": "course", "object_id": course_id}).properties.validity

        valid_until_ns := time.parse_rfc3339_ns(last_test_date) + years_to_ns(validity)

        time.now_ns() < valid_until_ns
}

# parses a "P<N>Y" ISO-8601 duration into nanoseconds, approximating a year
# as 365 days - good enough for a diploma validity window.
years_to_ns(duration) := ns if {
        m := regex.find_all_string_submatch_n(`^P(\d+)Y$`, duration, 1)
        years := to_number(m[0][1])
        ns := years * 365 * 24 * 60 * 60 * 1000000000
}

adres_id(postcode, huisnummer) := sprintf("%s-%d", [postcode, huisnummer])

adres(postcode, huisnummer) := obj if {
        obj := ds.object({"object_type": "adres", "object_id": adres_id(postcode, huisnummer)})
        obj != {}
}

adres_bestaat(postcode, huisnummer) if {
        adres(postcode, huisnummer)
}

adres_diplomatiek(postcode, huisnummer) if {
        adres(postcode, huisnummer).properties.diplomatiek == true
}

adres_laadpaal_aanwezig(postcode, huisnummer) if {
        adres(postcode, huisnummer).properties.laadpaal_aanwezig == true
}

adres_elektrisch_voertuig(postcode, huisnummer) if {
        adres(postcode, huisnummer).properties.elektrisch_voertuig == true
}
