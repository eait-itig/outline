import * as React from "react";
import Frame from "./components/Frame";
import Image from "./components/Image";

const URL_REGEX = new RegExp("^https?://docs.google.com/document/(.*)$");
type Props = {
  attrs: {
    href: string;
    matches: string[];
  };
};

export default class GoogleDocs extends React.Component<Props> {
  static ENABLED = [URL_REGEX];

  override render() {
    return (
      <Frame
        {...this.props}
        src={this.props.attrs.href.replace("/edit", "/preview")}
        icon={
          <Image
            src="/images/google-docs.png"
            alt="Google Docs Icon"
            width={16}
            height={16}
          />
        }
        canonicalUrl={this.props.attrs.href}
        title="Google Docs"
        border
      />
    );
  }
}
