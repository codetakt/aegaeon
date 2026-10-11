-- Read-only inventory. Keep stable row locations private; never print subjects.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

WITH inventory AS (
    SELECT environment_id, id AS end_user_id, status,
           subject = '' AS empty_subject,
           EXISTS (SELECT FROM generate_series(0, octet_length(convert_to(subject, 'UTF8')) - 1) AS bytes(i)
                   WHERE get_byte(convert_to(subject, 'UTF8'), bytes.i) > 127) AS non_ascii,
           octet_length(convert_to(subject, 'UTF8')) > 255 AS overlength
    FROM aegaeon.end_users
)
SELECT environment_id, status, count(*) AS total_rows,
       count(*) FILTER (WHERE empty_subject) AS empty_rows,
       count(*) FILTER (WHERE non_ascii) AS non_ascii_rows,
       count(*) FILTER (WHERE overlength) AS overlength_rows
FROM inventory
GROUP BY environment_id, status
ORDER BY environment_id, status;

WITH inventory AS (
    SELECT environment_id, id AS end_user_id, status,
           subject = '' AS empty_subject,
           EXISTS (SELECT FROM generate_series(0, octet_length(convert_to(subject, 'UTF8')) - 1) AS bytes(i)
                   WHERE get_byte(convert_to(subject, 'UTF8'), bytes.i) > 127) AS non_ascii,
           octet_length(convert_to(subject, 'UTF8')) > 255 AS overlength
    FROM aegaeon.end_users
)
SELECT * FROM inventory
WHERE empty_subject OR non_ascii OR overlength
ORDER BY environment_id, end_user_id;

ROLLBACK;
