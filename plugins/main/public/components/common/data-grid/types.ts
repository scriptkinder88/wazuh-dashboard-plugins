import { EuiDataGridColumn, EuiDataGridSorting } from '@elastic/eui';
import { EuiDataGridPaginationProps } from '@opensearch-project/oui';

export interface RenderColumnOptions {
  /**
   * Rendering context so a column render can adapt its layout:
   * - 'data-grid': cell inside the data grid (fixed height, truncate).
   * - 'doc-viewer': Document Details flyout (room to wrap, no truncation).
   */
  context?: 'data-grid' | 'doc-viewer';
}

export interface RenderColumn {
  render: (
    value: any,
    rowItem: object,
    options?: RenderColumnOptions,
  ) => string | React.ReactNode;
}

export interface ComputedColumn {
  /**
   * The column is not an index pattern field: its value comes only from
   * `render(value, rowItem)`. Such a column is listed with the index pattern
   * fields, cannot be sorted and has no filter cell actions.
   */
  computed?: boolean;
}

export type tDataGridColumn = Partial<RenderColumn> &
  ComputedColumn &
  EuiDataGridColumn;

export interface PaginationOptions
  extends Pick<
    EuiDataGridPaginationProps,
    'pageIndex' | 'pageSize' | 'pageSizeOptions'
  > {}

export type SortingColumns = EuiDataGridSorting['columns'];

export type tDataGridRenderColumn = RenderColumn & EuiDataGridColumn;
