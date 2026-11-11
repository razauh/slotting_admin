package com.slotting.admin.ops

import java.sql.Timestamp
import javax.sql.DataSource

class JdbcOpsNoticeRepository(
    private val openConnection: () -> java.sql.Connection,
) : OpsNoticeRepository {
    constructor(dataSource: DataSource) : this({ dataSource.connection })
    override fun open(notice: OpsNotice): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "insert into public.ops_notices (cause, class_tag, severity, notice_text, created_utc) values (?, ?, ?, ?, ?) on conflict (cause) do nothing",
            ).use { statement ->
                statement.setString(1, notice.cause)
                statement.setString(2, notice.classTag)
                statement.setString(3, notice.severity.name)
                statement.setString(4, notice.text)
                statement.setTimestamp(5, Timestamp.from(notice.createdAt))
                statement.executeUpdate() == 1
            }
        }

    override fun list(): List<OpsNotice> =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select cause, class_tag, severity, notice_text, created_utc from public.ops_notices order by case severity when 'CRITICAL' then 0 when 'WARNING' then 1 else 2 end, created_utc desc",
            ).use { statement ->
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(
                                OpsNotice(
                                    cause = rows.getString(1),
                                    classTag = rows.getString(2),
                                    severity = OpsSeverity.valueOf(rows.getString(3)),
                                    text = rows.getString(4),
                                    createdAt = rows.getTimestamp(5).toInstant(),
                                ),
                            )
                        }
                    }
                }
            }
        }

    override fun ack(cause: String): Boolean =
        openConnection().use { connection ->
            val updated = connection.prepareStatement(
                "update public.ops_notices set acknowledged_utc = now() where cause = ? and acknowledged_utc is null",
            ).use { statement ->
                statement.setString(1, cause)
                statement.executeUpdate()
            }
            if (updated > 0) {
                true
            } else {
                connection.prepareStatement("select 1 from public.ops_notices where cause = ?").use { statement ->
                    statement.setString(1, cause)
                    statement.executeQuery().use { it.next() }
                }
            }
        }
}

interface OpsDecisionSource {
    fun all(): List<OpsDecision>
}

class JdbcOpsDecisionRepository(
    private val openConnection: () -> java.sql.Connection,
) : OpsDecisionSource {
    constructor(dataSource: DataSource) : this({ dataSource.connection })
    override fun all(): List<OpsDecision> =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select item_name, owner, status, due_date, reopen_trigger from public.ops_decisions order by item_name",
            ).use { statement ->
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(
                                OpsDecision(
                                    itemName = rows.getString(1),
                                    owner = rows.getString(2),
                                    dueDate = rows.getDate(4)?.toLocalDate(),
                                    status = OpsDecisionStatus.valueOf(rows.getString(3)),
                                    reopenTrigger = rows.getString(5),
                                ),
                            )
                        }
                    }
                }
            }
        }
}
