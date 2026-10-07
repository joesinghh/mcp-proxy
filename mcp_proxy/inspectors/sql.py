import sqlglot
from sqlglot import exp
from typing import Set, Dict, Any, Optional
from mcp_proxy.inspectors.base import BaseInspector, ParserError


class SQLASTInspector(BaseInspector):
    """
    Inspects SQL queries using sqlglot AST parsing.
    Enforces read-only statements, prevents statement stacking/injection,
    and restricts table access to an explicit allowlist.
    """
    # Prohibited non-read-only statement types
    DISALLOWED_EXPRESSIONS = (
        exp.Drop,
        exp.Delete,
        exp.Update,
        exp.Insert,
        exp.Alter,
        exp.Create,
        exp.Command,
    )

    def __init__(
        self,
        allowed_tables: Optional[Set[str]] = None,
        dialect: str = "sqlite",
        allow_multi_statements: bool = False,
        field_name: str = "query"
    ):
        self.allowed_tables = {t.lower() for t in allowed_tables} if allowed_tables is not None else None
        self.dialect = dialect
        self.allow_multi_statements = allow_multi_statements
        self.field_name = field_name

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        query_str = args.get(self.field_name, "")
        if not isinstance(query_str, str) or not query_str.strip():
            raise ParserError(tool, self.field_name, f"Field '{self.field_name}' must be a non-empty string")

        query_str = query_str.strip()

        try:
            parsed = sqlglot.parse(query_str, read=self.dialect)
        except Exception as e:
            raise ParserError(tool, self.field_name, f"Malformed SQL syntax: {e}")

        # Filter out empty statements
        statements = [stmt for stmt in parsed if stmt is not None]
        if not statements:
            raise ParserError(tool, self.field_name, "SQL query contains no valid statements")

        # Statement stacking check
        if len(statements) > 1 and not self.allow_multi_statements:
            raise ParserError(
                tool,
                self.field_name,
                "Multi-statement SQL execution (query stacking) is forbidden"
            )

        for stmt in statements:
            self._inspect_statement(tool, stmt)

    def _inspect_statement(self, tool: str, stmt: exp.Expression) -> None:
        # Check against forbidden expressions
        if isinstance(stmt, self.DISALLOWED_EXPRESSIONS):
            stmt_name = type(stmt).__name__.upper()
            raise ParserError(tool, self.field_name, f"Destructive SQL operation '{stmt_name}' is forbidden")

        # Enforce read-only (must be a Select or Union)
        if not isinstance(stmt, (exp.Select, exp.Union)):
            stmt_name = type(stmt).__name__.upper()
            raise ParserError(tool, self.field_name, f"Operation '{stmt_name}' is not permitted; only read-only queries are allowed")

        # Check for nested destructive operations (e.g. inside subqueries or CTEs)
        for disallowed in self.DISALLOWED_EXPRESSIONS:
            if list(stmt.find_all(disallowed)):
                raise ParserError(tool, self.field_name, f"Embedded destructive SQL operation '{disallowed.__name__}' is forbidden")

        # Table allowlist enforcement
        if self.allowed_tables is not None:
            for table in stmt.find_all(exp.Table):
                t_name = table.name.lower()
                if t_name and t_name not in self.allowed_tables:
                    raise ParserError(
                        tool,
                        self.field_name,
                        f"Access to table '{t_name}' is forbidden. Allowed: {sorted(self.allowed_tables)}"
                    )
