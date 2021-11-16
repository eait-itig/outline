import { observable } from "mobx";
import { inject, observer } from "mobx-react";
import { EditIcon } from "outline-icons";
import queryString from "query-string";
import * as React from "react";
import { WithTranslation, withTranslation } from "react-i18next";
// @ts-expect-error ts-migrate(2305) FIXME: Module '"react-router-dom"' has no exported member... Remove this comment to see the full error message
import { RouterHistory } from "react-router-dom";
import "react-router-dom";
import styled from "styled-components";
import DocumentsStore from "stores/DocumentsStore";
import CollectionFilter from "scenes/Search/components/CollectionFilter";
import DateFilter from "scenes/Search/components/DateFilter";
import { Action } from "components/Actions";
import Empty from "components/Empty";
import Flex from "components/Flex";
import Heading from "components/Heading";
import InputSearchPage from "components/InputSearchPage";
import PaginatedDocumentList from "components/PaginatedDocumentList";
import Scene from "components/Scene";
import Subheading from "components/Subheading";
import NewDocumentMenu from "menus/NewDocumentMenu";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'types' or its corresponding ty... Remove this comment to see the full error message
import { LocationWithState } from "types";
import "types";

type Props = WithTranslation & {
  documents: DocumentsStore;
  history: RouterHistory;
  location: LocationWithState;
};

@observer
class Drafts extends React.Component<Props> {
  @observable
  params: URLSearchParams = new URLSearchParams(this.props.location.search);

  componentDidUpdate(prevProps: Props) {
    if (prevProps.location.search !== this.props.location.search) {
      this.handleQueryChange();
    }
  }

  handleQueryChange = () => {
    this.params = new URLSearchParams(this.props.location.search);
  };

  handleFilterChange = (search: {
    dateFilter?: string | null | undefined;
    collectionId?: string | null | undefined;
  }) => {
    this.props.history.replace({
      pathname: this.props.location.pathname,
      search: queryString.stringify(
        { ...queryString.parse(this.props.location.search), ...search },
        {
          skipEmptyString: true,
        }
      ),
    });
  };

  get collectionId() {
    const id = this.params.get("collectionId");
    return id ? id : undefined;
  }

  get dateFilter() {
    const id = this.params.get("dateFilter");
    return id ? id : undefined;
  }

  render() {
    const { t } = this.props;
    const { drafts, fetchDrafts } = this.props.documents;
    const isFiltered = this.collectionId || this.dateFilter;
    const options = {
      dateFilter: this.dateFilter,
      collectionId: this.collectionId,
    };
    return (
      <Scene
        icon={<EditIcon color="currentColor" />}
        title={t("Drafts")}
        actions={
          <>
            <Action>
              <InputSearchPage source="drafts" label={t("Search documents")} />
            </Action>
            <Action>
              <NewDocumentMenu />
            </Action>
          </>
        }
      >
        <Heading>{t("Drafts")}</Heading>
        <Subheading sticky>
          {t("Documents")}
          <Filters>
            <CollectionFilter
              collectionId={this.collectionId}
              onSelect={(collectionId) =>
                this.handleFilterChange({
                  collectionId,
                })
              }
            />
            <DateFilter
              dateFilter={this.dateFilter}
              onSelect={(dateFilter) =>
                this.handleFilterChange({
                  dateFilter,
                })
              }
            />
          </Filters>
        </Subheading>

        <PaginatedDocumentList
          empty={
            <Empty>
              {isFiltered
                ? t("No documents found for your filters.")
                : t("You’ve not got any drafts at the moment.")}
            </Empty>
          }
          fetch={fetchDrafts}
          documents={drafts(options)}
          options={options}
          showCollection
        />
      </Scene>
    );
  }
}

const Filters = styled(Flex)`
  opacity: 0.85;
  transition: opacity 100ms ease-in-out;
  position: absolute;
  right: -8px;
  bottom: 0;
  padding: 0 0 6px;

  &:hover {
    opacity: 1;
  }
`;

// @ts-expect-error ts-migrate(2344) FIXME: Type 'Drafts' does not satisfy the constraint 'Com... Remove this comment to see the full error message
export default withTranslation()<Drafts>(inject("documents")(Drafts));