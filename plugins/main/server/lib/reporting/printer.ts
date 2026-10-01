/*
 * Wazuh app - PDF report printer
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import path from 'path';
import PdfPrinter from 'pdfmake/src/printer';
import type { Logger } from 'opensearch_dashboards/server';
import {
  REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH,
  REPORTS_PAGE_FOOTER_TEXT,
  REPORTS_PAGE_HEADER_TEXT,
  REPORTS_PRIMARY_COLOR,
} from '../../../common/constants';

const COLORS = {
  PRIMARY: REPORTS_PRIMARY_COLOR,
};

export const REPORT_CUSTOMIZATION_LOGO = 'customization.logo.reports';
export const REPORT_CUSTOMIZATION_HEADER = 'customization.reports.header';
export const REPORT_CUSTOMIZATION_FOOTER = 'customization.reports.footer';

/**
 * Source of the report logo, header and footer. It has the shape of the
 * `getCustomizationSetting` method of the 4.x wazuh-core configuration, so the
 * printer can be wired to settings once 5.x exposes them again.
 */
export interface ReportCustomizationProvider {
  getCustomizationSetting: (
    ...settings: string[]
  ) => Promise<Record<string, string | undefined>>;
}

export const defaultReportCustomization: ReportCustomizationProvider = {
  getCustomizationSetting: () =>
    Promise.resolve({
      [REPORT_CUSTOMIZATION_LOGO]: REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH,
      [REPORT_CUSTOMIZATION_HEADER]: REPORTS_PAGE_HEADER_TEXT,
      [REPORT_CUSTOMIZATION_FOOTER]: REPORTS_PAGE_FOOTER_TEXT,
    }),
};

const ASSETS_PATH = path.join(__dirname, '../../../public/assets');

const pageConfiguration = ({ pathToLogo, pageHeader, pageFooter }) => ({
  styles: {
    h1: {
      fontSize: 22,
      monslight: true,
      color: COLORS.PRIMARY,
    },
    h2: {
      fontSize: 18,
      monslight: true,
      color: COLORS.PRIMARY,
    },
    h3: {
      fontSize: 16,
      monslight: true,
      color: COLORS.PRIMARY,
    },
    h4: {
      fontSize: 14,
      monslight: true,
      color: COLORS.PRIMARY,
    },
    standard: {
      color: '#333',
    },
    whiteColor: {
      color: '#FFF',
    },
  },
  pageMargins: [40, 80, 40, 80],
  header: {
    margin: [40, 20, 0, 0],
    columns: [
      {
        image: path.join(ASSETS_PATH, pathToLogo),
        fit: [190, 50],
      },
      {
        text: pageHeader,
        alignment: 'right',
        margin: [0, 0, 40, 0],
        color: COLORS.PRIMARY,
        width: 'auto',
      },
    ],
  },
  content: [],
  footer(currentPage: number, pageCount: number) {
    return {
      columns: [
        {
          text: pageFooter,
          color: COLORS.PRIMARY,
          margin: [40, 40, 0, 0],
        },
        {
          text: 'Page ' + currentPage.toString() + ' of ' + pageCount,
          alignment: 'right',
          margin: [0, 40, 40, 0],
          color: COLORS.PRIMARY,
          width: 'auto',
        },
      ],
    };
  },
});

const fonts = {
  Roboto: {
    normal: path.join(ASSETS_PATH, 'fonts/opensans/OpenSans-Light.ttf'),
    bold: path.join(ASSETS_PATH, 'fonts/opensans/OpenSans-Bold.ttf'),
    italics: path.join(ASSETS_PATH, 'fonts/opensans/OpenSans-Italic.ttf'),
    bolditalics: path.join(
      ASSETS_PATH,
      'fonts/opensans/OpenSans-BoldItalic.ttf',
    ),
    monslight: path.join(ASSETS_PATH, 'fonts/opensans/Montserrat-Light.ttf'),
  },
};

export class ReportPrinter {
  private _content: any[];
  private _printer: PdfPrinter;
  constructor(
    public logger: Logger,
    private customization: ReportCustomizationProvider = defaultReportCustomization,
  ) {
    this._printer = new PdfPrinter(fonts);
    this._content = [];
  }

  private processLongText(text: string, maxLength: number = 60): string {
    if (!text || typeof text !== 'string') {
      return text || '-';
    }

    if (text.length <= maxLength) {
      return text;
    }

    const words = text.split(' ');
    const lines: string[] = [];
    let currentLine = '';

    for (const word of words) {
      if (
        currentLine.length + (currentLine.length > 0 ? 1 : 0) + word.length >
        maxLength
      ) {
        if (currentLine.length > 0) {
          lines.push(currentLine);
        }

        if (word.length > maxLength) {
          const chunks = [];
          for (let i = 0; i < word.length; i += maxLength) {
            chunks.push(word.slice(i, i + maxLength));
          }
          for (let i = 0; i < chunks.length - 1; i++) {
            lines.push(chunks[i]);
          }
          currentLine = chunks[chunks.length - 1];
        } else {
          currentLine = word;
        }
      } else if (currentLine.length > 0) {
        currentLine += ' ' + word;
      } else {
        currentLine = word;
      }
    }

    if (currentLine.length > 0) {
      lines.push(currentLine);
    }

    return lines.join('\n');
  }

  /** Content added so far, as pdfmake nodes. */
  getContent() {
    return this._content;
  }

  addContent(...content: any) {
    this._content.push(...content);
    return this;
  }

  addSimpleTable({
    columns,
    items,
    title,
    widths: requestedWidths,
    fontSize = 8,
    maxTextLength = 60,
    margin,
    cellPadding,
  }: {
    columns: { id: string; label: string }[];
    title?: string | { text: string; style: string };
    items: any[];
    widths?: Array<number | string>;
    fontSize?: number;
    maxTextLength?: number;
    margin?: number[];
    cellPadding?: number;
  }) {
    if (title) {
      this.addContent(
        typeof title === 'string' ? { text: title, style: 'h4' } : title,
      ).addNewLine();
    }

    if (!items || !items.length) {
      this.addContent({
        text: 'No results match your search criteria',
        style: 'standard',
      });
      return this;
    }

    const tableHeader = columns.map(column => {
      return { text: column.label, style: 'whiteColor', border: [0, 0, 0, 0] };
    });

    const tableRows = items.map(item => {
      return columns.map(column => {
        const cellValue = item[column.id];
        return {
          text: this.processLongText(
            typeof cellValue !== 'undefined' ? String(cellValue) : '-',
            maxTextLength,
          ),
          style: 'standard',
        };
      });
    });

    let widths: Array<number | string> = [];

    if (
      Array.isArray(requestedWidths) &&
      requestedWidths.length === columns.length
    ) {
      widths = requestedWidths;
    } else {
      // 385 is the max initial width per column in portrait reports.
      let totalLength = columns.length - 1;
      const widthColumn = 385 / totalLength;
      let totalWidth = totalLength * widthColumn;

      for (let step = 0; step < columns.length - 1; step++) {
        const columnLength = this.getColumnWidth(
          columns[step],
          tableRows,
          step,
        );

        if (columnLength <= Math.round(totalWidth / totalLength)) {
          widths.push(columnLength);
          totalWidth -= columnLength;
        } else {
          widths.push(Math.round(totalWidth / totalLength));
          totalWidth -= Math.round(totalWidth / totalLength);
        }
        totalLength--;
      }
      widths.push('*');
    }

    const compactPadding =
      typeof cellPadding === 'number'
        ? {
            paddingLeft: () => cellPadding,
            paddingRight: () => cellPadding,
            paddingTop: () => cellPadding,
            paddingBottom: () => cellPadding,
          }
        : {};

    this.addContent({
      fontSize,
      ...(Array.isArray(margin) ? { margin } : {}),
      table: {
        headerRows: 1,
        widths,
        body: [tableHeader, ...tableRows],
      },
      layout: {
        fillColor: (i: number) => (i === 0 ? COLORS.PRIMARY : null),
        hLineColor: () => COLORS.PRIMARY,
        hLineWidth: () => 1,
        vLineWidth: () => 0,
        ...compactPadding,
      },
    }).addNewLine();
    return this;
  }

  addNewLine() {
    return this.addContent({ text: '\n' });
  }

  addContentWithNewLine(title: any) {
    return this.addContent(title).addNewLine();
  }

  /**
   * Renders the report and returns the PDF document.
   */
  async printToBuffer(): Promise<Buffer> {
    const {
      [REPORT_CUSTOMIZATION_LOGO]: pathToLogo,
      [REPORT_CUSTOMIZATION_HEADER]: pageHeader,
      [REPORT_CUSTOMIZATION_FOOTER]: pageFooter,
    } = await this.customization.getCustomizationSetting(
      REPORT_CUSTOMIZATION_LOGO,
      REPORT_CUSTOMIZATION_HEADER,
      REPORT_CUSTOMIZATION_FOOTER,
    );

    return new Promise((resolve, reject) => {
      try {
        const document = this._printer.createPdfKitDocument({
          ...pageConfiguration({
            pathToLogo: pathToLogo || REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH,
            pageHeader: pageHeader ?? REPORTS_PAGE_HEADER_TEXT,
            pageFooter: pageFooter ?? REPORTS_PAGE_FOOTER_TEXT,
          }),
          content: this._content,
        });
        const chunks: Buffer[] = [];

        document.on('data', (chunk: Buffer) => chunks.push(chunk));
        document.on('error', reject);
        document.on('end', () => resolve(Buffer.concat(chunks)));
        document.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Returns the width of a given column
   *
   * @param column
   * @param tableRows
   * @param index
   * @returns {number}
   */
  getColumnWidth(column, tableRows, index) {
    const widthCharacter = 5; // min width per character

    // Get the longest row value
    const maxRowLength = tableRows.reduce((maxLength, row) => {
      return row[index].text.length > maxLength
        ? row[index].text.length
        : maxLength;
    }, 0);

    // Get column name length
    const headerLength = column.label.length;

    // Use the longest to get the column width
    const maxLength = maxRowLength > headerLength ? maxRowLength : headerLength;

    return maxLength * widthCharacter;
  }
}
