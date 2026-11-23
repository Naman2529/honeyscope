-- One row per attacker session. This is the unit everything downstream
-- (rules, clustering, anomaly scores, ranking) works on.
CREATE OR REPLACE VIEW sessions AS
WITH base AS (
    SELECT
        session,
        any_value(src_ip)                                           AS src_ip,
        min(ts)                                                     AS start_ts,
        max(ts)                                                     AS end_ts,
        max(duration_s)                                             AS duration_s,
        any_value(version) FILTER (WHERE eventid = 'cowrie.client.version') AS client_version,
        any_value(hassh)   FILTER (WHERE eventid = 'cowrie.client.kex')     AS hassh,

        count(*) FILTER (WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success')
                           AND password IS NOT NULL)                AS n_password_attempts,
        count(*) FILTER (WHERE eventid = 'cowrie.client.fingerprint') AS n_pubkey_attempts,
        count(*) FILTER (WHERE eventid = 'cowrie.login.failed')     AS n_login_failed,
        count(*) FILTER (WHERE eventid = 'cowrie.login.success') > 0 AS login_success,
        arg_min(username, ts) FILTER (WHERE eventid = 'cowrie.login.success') AS success_user,
        arg_min(password, ts) FILTER (WHERE eventid = 'cowrie.login.success') AS success_pass,

        count(*) FILTER (WHERE eventid = 'cowrie.command.input')    AS n_commands,
        count(DISTINCT input) FILTER (WHERE eventid = 'cowrie.command.input') AS n_unique_commands,
        string_agg(input, ' ; ' ORDER BY ts)
            FILTER (WHERE eventid = 'cowrie.command.input')         AS commands,

        count(*) FILTER (WHERE eventid IN ('cowrie.session.file_download',
                                           'cowrie.session.file_upload')) AS n_file_transfers,
        string_agg(DISTINCT url, ' ')
            FILTER (WHERE eventid = 'cowrie.session.file_download') AS download_urls
    FROM events
    WHERE session IS NOT NULL
    GROUP BY session
)
SELECT
    *,
    -- fallback if session.closed hasn't been logged yet (session still open)
    coalesce(duration_s, epoch(end_ts) - epoch(start_ts)) AS duration_est_s,
    hour(start_ts)                                        AS start_hour_utc
FROM base;
