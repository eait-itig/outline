import { Table, TBody, TR, TD } from "oy-vey";
import * as React from "react";
import EmptySpace from "./EmptySpace";

const url = process.env.CDN_URL || process.env.URL;
export default () => {
  return (
    <Table width="100%">
      <TBody>
        <TR>
          <TD>
            <EmptySpace height={40} />
            <img
              alt="Outline"
              src={`${url}/email/header-logo.png`}
              height="48"
              width="48"
            />
          </TD>
        </TR>
      </TBody>
    </Table>
  );
};
