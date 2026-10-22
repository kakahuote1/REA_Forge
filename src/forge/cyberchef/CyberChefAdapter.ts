import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  cyberChefReportSchema,
  type CyberChefReport,
  type ForgeCyberChefOperation,
} from "../../domain/forge/cyberChef.js";
export class CyberChefAdapter extends OwnedStaticHelper<
  ForgeCyberChefOperation,
  CyberChefReport
> {
  constructor() {
    super(
      "forge-cyberchef",
      "bridge/forge/cyberchef/worker.py",
      cyberChefReportSchema,
    );
  }
}
