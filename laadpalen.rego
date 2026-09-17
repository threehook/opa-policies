package authz

import rego.v1

# Laadpalen example policy.
#
# Two decisions, both requiring department membership AND an unexpired
# "laadpalen-management" diploma:
#   - request_laadpaal_citizen:   burgerzaken members may request a laadpaal for a citizen
#   - request_laadpaal_diplomaat: bestuursbureau members may request a laadpaal for a diplomaat
#
# A course carries a `validity` property (an ISO-8601 duration, e.g. "P1Y");
# a diploma carries a `last_test_date` (RFC3339). A diploma is valid while
# now() < last_test_date + validity.
#
# NOTE: only whole-year durations ("P<N>Y") are parsed - that's the only form
# the laadpalen-management course actually uses, this is not a general
# ISO-8601 duration parser.

default request_laadpaal_citizen = false

request_laadpaal_citizen if {
        is_department_member("burgerzaken")
        has_valid_diploma("laadpalen-management")
}

default request_laadpaal_diplomaat = false

request_laadpaal_diplomaat if {
        is_department_member("bestuursbureau")
        has_valid_diploma("laadpalen-management")
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

# true if the current user holds an unexpired diploma for the given course.
has_valid_diploma(course_id) if {
        some diploma_id in diploma_ids_for_course(course_id)

        ds.check({
                "object_type": "diploma",
                "object_id": diploma_id,
                "relation": "holder",
                "subject_type": "user",
                "subject_id": input.user.id,
        })

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
