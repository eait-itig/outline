import { observer } from "mobx-react";
import { CloseIcon } from "outline-icons";
import * as React from "react";
import { useTranslation } from "react-i18next";
import { useHistory, useRouteMatch } from "react-router-dom";
import styled from "styled-components";
import breakpoint from "styled-components-breakpoint";
import Event from "models/Event";
import Button from "components/Button";
import Empty from "components/Empty";
import Flex from "components/Flex";
import PaginatedEventList from "components/PaginatedEventList";
import Scrollable from "components/Scrollable";
import useStores from "hooks/useStores";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/routeHelpers' or its cor... Remove this comment to see the full error message
import { documentUrl } from "utils/routeHelpers";

// @ts-expect-error ts-migrate(7034) FIXME: Variable 'EMPTY_ARRAY' implicitly has type 'any[]'... Remove this comment to see the full error message
const EMPTY_ARRAY = [];

function DocumentHistory() {
  const { events, documents } = useStores();
  const { t } = useTranslation();
  const match = useRouteMatch();
  const history = useHistory();
  // @ts-expect-error ts-migrate(2339) FIXME: Property 'documentSlug' does not exist on type '{}... Remove this comment to see the full error message
  const document = documents.getByUrl(match.params.documentSlug);
  const eventsInDocument = document
    ? events.inDocument(document.id)
    // @ts-expect-error ts-migrate(7005) FIXME: Variable 'EMPTY_ARRAY' implicitly has an 'any[]' t... Remove this comment to see the full error message
    : EMPTY_ARRAY;

  const onCloseHistory = () => {
    history.push(documentUrl(document));
  };

  const items = React.useMemo(() => {
    if (
      eventsInDocument[0] &&
      document &&
      eventsInDocument[0].createdAt !== document.updatedAt
    ) {
      eventsInDocument.unshift(
        // @ts-expect-error ts-migrate(2554) FIXME: Expected 2 arguments, but got 1.
        new Event({
          name: "documents.latest_version",
          documentId: document.id,
          createdAt: document.updatedAt,
          actor: document.updatedBy,
        })
      );
    }

    return eventsInDocument;
  }, [eventsInDocument, document]);
  return (
    <Sidebar>
      {document ? (
        <Position column>
          <Header>
            <Title>{t("History")}</Title>
            <Button
              icon={<CloseIcon />}
              onClick={onCloseHistory}
              borderOnHover
              neutral
            />
          </Header>
          <Scrollable topShadow>
            <PaginatedEventList
              fetch={events.fetchPage}
              events={items}
              options={{
                documentId: document.id,
              }}
              document={document}
              empty={<Empty>{t("Oh weird, there's nothing here")}</Empty>}
            />
          </Scrollable>
        </Position>
      ) : null}
    </Sidebar>
  );
}

const Position = styled(Flex)`
  position: fixed;
  top: 0;
  bottom: 0;
  width: ${(props) => props.theme.sidebarWidth}px;
`;
const Sidebar = styled(Flex)`
  display: none;
  position: relative;
  flex-shrink: 0;
  background: ${(props) => props.theme.background};
  width: ${(props) => props.theme.sidebarWidth}px;
  border-left: 1px solid ${(props) => props.theme.divider};
  z-index: 1;

  ${breakpoint("tablet")`
    display: flex;
  `};
`;
const Title = styled(Flex)`
  font-size: 16px;
  font-weight: 600;
  text-align: center;
  align-items: center;
  justify-content: flex-start;
  text-overflow: ellipsis;
  white-space: nowrap;
  overflow: hidden;
  width: 0;
  flex-grow: 1;
`;
const Header = styled(Flex)`
  align-items: center;
  position: relative;
  padding: 12px;
  color: ${(props) => props.theme.text};
  flex-shrink: 0;
`;

export default observer(DocumentHistory);