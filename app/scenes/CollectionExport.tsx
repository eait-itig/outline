import { observer } from "mobx-react";
import * as React from "react";
import { useTranslation, Trans } from "react-i18next";
import Collection from "models/Collection";
import Button from "components/Button";
import Flex from "components/Flex";
import HelpText from "components/HelpText";
import useToasts from "hooks/useToasts";

type Props = {
  collection: Collection;
  onSubmit: () => void;
};

function CollectionExport({ collection, onSubmit }: Props) {
  const [isLoading, setIsLoading] = React.useState();
  const { t } = useTranslation();
  const { showToast } = useToasts();
  const handleSubmit = React.useCallback(
    async (ev: React.SyntheticEvent) => {
      ev.preventDefault();
      // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'true' is not assignable to param... Remove this comment to see the full error message
      setIsLoading(true);
      await collection.export();
      // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'false' is not assignable to para... Remove this comment to see the full error message
      setIsLoading(false);
      showToast(
        t("Export started, you will receive an email when it’s complete.")
      );
      onSubmit();
    },
    [collection, onSubmit, showToast, t]
  );
  return (
    <Flex column>
      <form onSubmit={handleSubmit}>
        <HelpText>
          <Trans
            defaults="Exporting the collection <em>{{collectionName}}</em> may take a few seconds. Your documents will be a zip of folders with files in Markdown format. Please visit the Export section on settings to get the zip."
            values={{
              collectionName: collection.name,
            }}
            components={{
              em: <strong />,
            }}
          />
        </HelpText>
        // @ts-expect-error ts-migrate(2322) FIXME: Type 'undefined' is not
        assignable to type 'boolea... Remove this comment to see the full error
        message
        <Button type="submit" disabled={isLoading} primary>
          // @ts-expect-error ts-migrate(2322) FIXME: Type 'string |
          HTMLCollection' is not assignable t... Remove this comment to see the
          full error message
          {isLoading ? `${t("Exporting")}…` : t("Export Collection")}
        </Button>
      </form>
    </Flex>
  );
}

export default observer(CollectionExport);