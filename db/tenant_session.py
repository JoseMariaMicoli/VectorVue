"""Tenant-aware SQLAlchemy session wrapper for Phase 6.5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import and_
from sqlalchemy import bindparam
from sqlalchemy.orm import Session
from sqlalchemy.sql import Delete, Select, Update
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import BinaryExpression, BindParameter
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.visitors import traverse


class SecurityError(RuntimeError):
    """Raised when tenant-boundary enforcement is violated."""


@dataclass(frozen=True)
class TenantConstraintState:
    present: bool = False
    mismatched: bool = False


class TenantSession:
    """Session guard that enforces tenant isolation for all query operations.

    - Requires tenant_id at construction
    - Injects tenant filter in SELECT statements
    - Blocks UPDATE/DELETE without explicit tenant filter
    - Raises SecurityError on cross-tenant expressions
    """

    def __init__(self, session: Session, tenant_id: UUID | str):
        if tenant_id is None:
            raise ValueError("tenant_id is required")
        self._session = session
        self.tenant_id = str(tenant_id)

    def execute(self, statement, *args, **kwargs):
        if isinstance(statement, Select):
            self._assert_no_cross_tenant_filter(statement)
            statement = self._inject_tenant_filter(statement)
            return self._session.execute(statement, *args, **kwargs)

        if isinstance(statement, (Update, Delete)):
            self._enforce_mutation_constraints(statement)
            statement = self._inject_tenant_filter(statement)
            return self._session.execute(statement, *args, **kwargs)

        return self._session.execute(statement, *args, **kwargs)

    def scalar(self, statement, *args, **kwargs):
        return self.execute(statement, *args, **kwargs).scalar()

    def scalars(self, statement, *args, **kwargs):
        return self.execute(statement, *args, **kwargs).scalars()

    def add(self, obj: Any):
        # Attach tenant automatically for tenant-scoped ORM inserts.
        if hasattr(obj, "tenant_id") and getattr(obj, "tenant_id", None) in (None, ""):
            setattr(obj, "tenant_id", self.tenant_id)
        elif hasattr(obj, "tenant_id") and str(getattr(obj, "tenant_id")) != self.tenant_id:
            raise SecurityError("Cross-tenant insert blocked")
        self._session.add(obj)

    def commit(self):
        self._session.commit()

    def rollback(self):
        self._session.rollback()

    def close(self):
        self._session.close()

    def _inject_tenant_filter(self, statement):
        where_clause = self._tenant_where_for_statement(statement)
        if where_clause is None:
            return statement
        return statement.where(where_clause)

    def _tenant_where_for_statement(self, statement):
        clauses = []
        for from_obj in statement.get_final_froms():
            columns = getattr(from_obj, "c", None)
            if columns is None:
                continue
            tenant_col = columns.get("tenant_id")
            if tenant_col is not None:
                clauses.append(tenant_col == bindparam("_tenant_id", self.tenant_id))
        if not clauses:
            return None
        return and_(*clauses)

    def _assert_no_cross_tenant_filter(self, statement):
        state = self._inspect_tenant_constraints(statement)
        if state.mismatched:
            raise SecurityError("Cross-tenant access attempt blocked")

    def _enforce_mutation_constraints(self, statement):
        state = self._inspect_tenant_constraints(statement)
        if state.mismatched:
            raise SecurityError("Cross-tenant mutation attempt blocked")
        if not state.present:
            raise SecurityError("UPDATE/DELETE requires explicit tenant_id filter")

    def _inspect_tenant_constraints(self, statement) -> TenantConstraintState:
        state = {"present": False, "mismatched": False}

        def visit_binary(binary: BinaryExpression):
            left = binary.left
            right = binary.right
            op = binary.operator

            if self._is_tenant_column(left):
                self._evaluate_constraint_value(right, op, state)
            elif self._is_tenant_column(right):
                self._evaluate_constraint_value(left, op, state)

        for criterion in getattr(statement, "_where_criteria", ()):
            traverse(criterion, {}, {"binary": visit_binary})

        return TenantConstraintState(present=state["present"], mismatched=state["mismatched"])

    def _evaluate_constraint_value(self, value_expr, operator, state: dict[str, bool]):
        if operator not in (operators.eq, operators.is_):
            return
        state["present"] = True
        value = self._literal_from_expression(value_expr)
        if value is None:
            return
        if str(value) != self.tenant_id:
            state["mismatched"] = True

    @staticmethod
    def _is_tenant_column(expr: Any) -> bool:
        if isinstance(expr, Column) and expr.key == "tenant_id":
            return True
        return getattr(expr, "key", None) == "tenant_id"

    @staticmethod
    def _literal_from_expression(expr: Any):
        if isinstance(expr, BindParameter):
            return expr.value
        if hasattr(expr, "value"):
            return getattr(expr, "value")
        return None
